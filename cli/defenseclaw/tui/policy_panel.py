# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel behaviour for the Textual TUI (key ``P``).

:class:`PolicyPanelMixin` is mixed into ``DefenseClawTUI``. It owns the
panel's I/O: reading the policy catalog (named policies and guardrail rule
packs, in-process through :mod:`defenseclaw.policy_catalog` on a thread),
listing sandbox packs (``defenseclaw sandbox pack list -o json``), validating
a rule pack (``guardrail validate-pack PATH --json``), and the two change
flows: pick a policy → confirm → ``policy activate NAME``, and pick a scope
and a pack → validate → confirm → ``guardrail use-pack PACK [--connector C]``.

The pure state lives in :mod:`defenseclaw.tui.services.policy_state`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from rich.markup import escape as rich_escape

from defenseclaw.platform_support import openshell_sandboxes_supported
from defenseclaw.tui.screens.consequence import (
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.screens.policy_picker import PolicyPickerScreen
from defenseclaw.tui.screens.rule_pack_picker import (
    PackOption,
    PackScope,
    RulePackChoice,
    RulePackPickerScreen,
)
from defenseclaw.tui.services.policy_state import (
    VIEW_TITLES,
    PackValidation,
    PoliciesPanelModel,
    PolicyPanelAction,
    activate_intent,
    fit,
    pack_weakens,
    parse_validation,
    policy_side_effects,
    policy_weakenings,
    use_pack_intent,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS

# Buttons of the panel's control bar, mapped to the key they press.
POLICY_BUTTON_KEYS: dict[str, str] = {
    "policies-view-policies": "1",
    "policies-view-packs": "2",
    "policies-view-sandbox": "3",
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


def read_policy_catalog(config: object | None) -> PolicyCatalogRead:
    """Blocking read of named policies and rule packs (run it in a thread)."""
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
        if self._policy_model_injected or self._policy_load_running:
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
        if read.error:
            model.set_error(read.error)
        else:
            model.apply_policies(read.policies)
        if read.pack_error:
            model.set_pack_error(read.pack_error)
        else:
            model.apply_packs(read.global_pack, read.connectors, read.packs)
        self._policy_publish_active()
        if getattr(self, "active_panel", "") in {"policies", "overview"} and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

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

    def _policies_body_text(self) -> str:
        """Two lines: the view tabs, then the headline. Keys live in the hint bar."""
        model = self.policy_model
        size = getattr(self, "size", None)
        width = max(40, int(getattr(size, "width", 0) or 120) - 8)
        tabs = "  ".join(
            f"[bold reverse] {index} {VIEW_TITLES[view]} [/]"
            if view == model.view
            else f"[{TOKENS.text_muted}]{index} {VIEW_TITLES[view]}[/]"
            for index, view in enumerate(model.views(), start=1)
        )
        headline = model.headline()
        failed = (
            model.error
            or (model.view == "packs" and model.pack_error)
            or (model.view == "sandbox_packs" and model.sandbox_error)
        )
        color = TOKENS.accent_amber if failed else TOKENS.text_secondary
        lines = [
            f"[bold {TOKENS.accent_cyan}]Policies[/]  {tabs}",
            f"[{color}]{rich_escape(fit(headline, width))}[/]",
        ]
        empty = model.empty_state()
        if empty:
            lines[1] = f"[{TOKENS.text_secondary}]{rich_escape(fit(empty, width))}[/]"
        return "\n".join(lines)

    def _sync_policy_controls(self) -> None:
        model = self.policy_model
        view = model.view
        visible = {
            "policies-view-policies": True,
            "policies-view-packs": True,
            "policies-view-sandbox": model.sandbox_supported,
            "policies-activate": view == "policies" and model.selected_policy() is not None,
            "policies-change-pack": view == "packs" and model.global_pack is not None,
            "policies-details": model.row_count() > 0,
            "policies-refresh": True,
        }
        for button_id, show in visible.items():
            self._set_button_visible(f"#{button_id}", show)  # type: ignore[attr-defined]
        for button_id, target in (
            ("policies-view-policies", "policies"),
            ("policies-view-packs", "packs"),
            ("policies-view-sandbox", "sandbox_packs"),
        ):
            self._set_button_active(f"#{button_id}", view == target)  # type: ignore[attr-defined]

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
        if kind == "refresh":
            self._schedule_policy_load(sandbox=self.policy_model.sandbox_loaded)
        elif kind == "load_sandbox_packs":
            self._schedule_policy_load(sandbox=True)
        elif kind == "pick_policy":
            self.run_worker(self._policy_activate_flow(action.policy), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        elif kind == "pick_pack":
            self.run_worker(self._rule_pack_flow(action.connector), exclusive=False, thread=False)  # type: ignore[attr-defined]
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
        await self._confirm_and_run_intent(activate_intent(name))  # type: ignore[attr-defined]

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
        await self._confirm_and_run_intent(use_pack_intent(choice.pack, choice.connector))  # type: ignore[attr-defined]


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
        title=f"Activate the {chosen.name} policy?",
        summary=f"{before} → {chosen.name}",
        details=tuple(rich_escape(line) for line in details),
        consequence=rich_escape(consequence),
        actions=(
            ConsequenceAction(
                action_id="activate",
                hotkey="a",
                label=f"Activate {rich_escape(chosen.name)}",
                description="Shows the command before it runs.",
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
    details.append(f"Validation: {choice.validation.summary}")
    command = " ".join(use_pack_intent(choice.pack, connector).argv)
    details.append(f"Runs: {fit(command, 72)}")
    consequence = ""
    if weaker:
        consequence = f"{choice.name} is a looser preset than {', '.join(sorted(set(replaced)))}."
    elif choice.validation.state == "unavailable":
        consequence = "The validator is unavailable; the preset is used without checking it."
    where = connector or "every connector"
    return ConsequenceModalModel(
        title=f"Use the {choice.name} rule pack for {where}?",
        summary="The gateway applies the new pack without a restart.",
        details=tuple(rich_escape(line) for line in details),
        consequence=rich_escape(consequence),
        actions=(
            ConsequenceAction(
                action_id="use",
                hotkey="u",
                label=f"Use {rich_escape(choice.name)}",
                description="Shows the command before it runs.",
                variant="error" if weaker else "primary",
                danger=weaker,
            ),
        ),
        default_action_id="use",
        border_color=TOKENS.accent_red if weaker else TOKENS.border_active,
    )


__all__ = [
    "POLICY_BUTTON_KEYS",
    "PolicyCatalogRead",
    "PolicyPanelMixin",
    "policy_change_modal",
    "read_policy_catalog",
    "rule_pack_change_modal",
]
