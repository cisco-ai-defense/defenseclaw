# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Routing panel I/O for DefenseClawTUI (the model is services/routing_state.py).

Reads run ``defenseclaw routing status --json`` and ``routing usage --json``
in workers; every change is a ``defenseclaw routing ...`` command the user
previews (destructive ones through the consequence modal).
"""

from __future__ import annotations

from defenseclaw.tui.markup_safe import escape as rich_escape
from defenseclaw.tui.screens.field_editor import FieldEditorScreen
from defenseclaw.tui.services.routing_state import (
    VIEW_USAGE,
    RoutingPanelAction,
    RoutingPanelModel,
    overview_tile,
)

ROUTING_PROMPTS = {
    "test": ("Test a prompt", "Type a prompt; DefenseClaw shows which model it would go to. No model is called."),
    "model": ("Add a model", "Alias, provider and model, for example: fast anthropic claude-haiku-4-5"),
}

class RoutingPanelMixin:
    """Routing panel wiring; DefenseClawTUI supplies run_worker and the intent runner."""

    routing_model: RoutingPanelModel

    def _routing_init(self, routing_model: RoutingPanelModel | None = None) -> None:
        self._routing_model_injected = routing_model is not None
        self.routing_model = routing_model or RoutingPanelModel()
        self._routing_load_running = False
        self._routing_load_pending = False

    def _routing_tab_wanted(self) -> bool:
        """The Routing tab shows while routing is on or routing.admin is set."""
        routing = getattr(getattr(self, "config", None), "routing", None)
        return bool(getattr(routing, "enabled", False) or getattr(routing, "admin", None))

    def _routing_mount(self) -> None:
        """Fill the Overview routing line once at start, only when routing is on."""
        routing = getattr(getattr(self, "config", None), "routing", None)
        if getattr(routing, "enabled", False):
            self._schedule_routing_load()

    def _schedule_routing_load(self) -> None:
        if getattr(self, "_app_shutting_down", False) or self._routing_model_injected:
            return
        if self._routing_load_running:
            self._routing_load_pending = True
            return
        self._routing_load_running = True
        self.run_worker(self._load_routing(), exclusive=False, thread=False)  # type: ignore[attr-defined]

    async def _load_routing(self) -> None:
        from defenseclaw.tui.app import _communicate_captured

        model = self.routing_model
        try:
            code, out, err = await _communicate_captured("defenseclaw", ("routing", "status", "--json"))
            if code == 0:
                model.apply_status_json(out)
            else:
                model.set_error(_first_line(err) or "defenseclaw routing status failed; run it in a terminal to see why")
            if model.view == VIEW_USAGE:
                code, out, err = await _communicate_captured(
                    "defenseclaw", ("routing", "usage", "--json", "--since", model.usage_since())
                )
                if code == 0:
                    model.apply_usage_json(out)
                else:
                    model.usage = {"rows": [], "error": _first_line(err) or "usage is not available"}
        except Exception as exc:  # noqa: BLE001 - never a stack trace in the TUI
            model.set_error(f"routing status failed: {exc}")
        finally:
            self._routing_load_running = False
        overview = getattr(self, "overview_model", None)
        if overview is not None and hasattr(overview, "set_routing_tile"):
            overview.set_routing_tile(overview_tile(model.status) if model.enabled else "")
        if self._routing_load_pending:
            self._routing_load_pending = False
            self._schedule_routing_load()
        if getattr(self, "active_panel", "") == "routing":
            self._update_body_only()  # type: ignore[attr-defined]

    def _routing_body_text(self) -> str:
        model = self.routing_model
        lines = [rich_escape(model.summary_line())]
        warnings = model.warnings()
        if warnings and model.view != VIEW_USAGE:
            more = f" (+{len(warnings) - 1} more: defenseclaw routing status)" if len(warnings) > 1 else ""
            lines.append("[yellow]" + rich_escape(warnings[0]) + more + "[/]")
        empty = not (model.usage_rows() if model.view == VIEW_USAGE else model.rows())
        if model.loaded and empty and not model.error:
            lines.append(rich_escape(model.empty_state()))
        return "\n".join(lines)

    def _apply_routing_action(self, action: RoutingPanelAction) -> bool:
        kind = action.kind
        if kind == "none":
            if action.hint:
                self._set_status(action.hint)  # type: ignore[attr-defined]
                return True
            return False
        if kind == "move":
            self._update_body_only()  # type: ignore[attr-defined]
            return True
        if kind in ("view", "refresh"):
            self._schedule_routing_load()
            self._update_body_only()  # type: ignore[attr-defined]
            return True
        if kind == "intent" and action.intent is not None:
            self.run_worker(self._confirm_and_run_intent(action.intent), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        if kind == "prompt":
            self._open_routing_prompt(action.prompt)
            return True
        return False

    def _open_routing_prompt(self, prompt: str) -> None:
        title, hint = ROUTING_PROMPTS[prompt]

        def done(value: str | None) -> None:
            if value is None:
                self._set_status("Cancelled.")  # type: ignore[attr-defined]
                return
            intent = self.routing_model.intent_for_prompt(prompt, value)
            if intent is None:
                self._set_status(f"{title}: {hint}")  # type: ignore[attr-defined]
                return
            self.run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)  # type: ignore[attr-defined]

        self.push_screen(FieldEditorScreen(title, hint=hint), done)  # type: ignore[attr-defined]

    def _routing_command_done(self) -> None:
        """After a routing command: re-read config.yaml, the status, and show
        the tab once routing applies (setup or enable from the wizard or the
        palette) without a restart."""
        refresh = getattr(self, "_refresh_cached_config", None)
        if callable(refresh):
            refresh()
        self._schedule_routing_load()
        if self._routing_tab_wanted():
            self._ensure_routing_tab()

    def _ensure_routing_tab(self) -> None:
        from textual.widgets import Tab, Tabs

        try:
            tabs = self.query_one("#tabs", Tabs)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - no tab strip (tests, early start)
            return
        if any(tab.id == "tab-routing" for tab in tabs.query(Tab)):
            return
        tabs.add_tab(Tab("M Routing", id="tab-routing"))


def _first_line(stderr: bytes | str) -> str:
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr or "")
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""
