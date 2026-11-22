# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Vault panel I/O for DefenseClawTUI (the model is services/vault_state.py).

Reads run ``defenseclaw sandbox vault list --json`` in a worker; every change
is a ``defenseclaw sandbox vault ...`` command the user previews (remove
through the consequence modal). A value is typed in a hidden field and goes
to the command on standard input; the panel never shows one.
"""

from __future__ import annotations

from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.markup_safe import escape as rich_escape
from defenseclaw.tui.screens.field_editor import FieldEditorScreen
from defenseclaw.tui.services.vault_state import VaultPanelAction, VaultPanelModel


class VaultPanelMixin:
    """Vault panel wiring; DefenseClawTUI supplies run_worker and the intent runner."""

    vault_model: VaultPanelModel

    def _vault_init(self, vault_model: VaultPanelModel | None = None) -> None:
        self._vault_model_injected = vault_model is not None
        self.vault_model = vault_model or VaultPanelModel()
        self._vault_load_running = False
        self._vault_load_pending = False

    def _vault_tab_wanted(self) -> bool:
        """The Vault tab shows where sandboxes run (Linux and macOS)."""
        from defenseclaw.platform_support import openshell_sandboxes_supported

        return bool(openshell_sandboxes_supported())

    def _schedule_vault_load(self) -> None:
        if getattr(self, "_app_shutting_down", False) or self._vault_model_injected:
            return
        if self._vault_load_running:
            self._vault_load_pending = True
            return
        self._vault_load_running = True
        self.run_worker(self._load_vault(), exclusive=False, thread=False)  # type: ignore[attr-defined]

    async def _load_vault(self) -> None:
        from defenseclaw.tui.app import _communicate_captured
        from defenseclaw.tui.routing_panel import _plain_error

        model = self.vault_model
        try:
            code, out, err = await _communicate_captured("defenseclaw", ("sandbox", "vault", "list", "--json"))
            if code == 0:
                model.apply_list_json(out)
            else:
                model.set_error(_plain_error(err, "defenseclaw sandbox vault list failed; run it in a terminal to see why"))
        except Exception as exc:  # noqa: BLE001 - never a stack trace in the TUI
            model.set_error(f"the vault could not be read: {exc}")
        finally:
            self._vault_load_running = False
        if self._vault_load_pending:
            self._vault_load_pending = False
            self._schedule_vault_load()
        if getattr(self, "active_panel", "") == "vault":
            self._render_chrome()  # type: ignore[attr-defined]

    def _vault_body_text(self) -> str:
        model = self.vault_model
        lines = [rich_escape(model.summary_line())]
        if model.loaded and not model.error:
            if model.entries:
                lines.append("[dim]" + rich_escape(model.detail_line()) + "[/]")
            else:
                lines.append(rich_escape(model.empty_state()))
        return "\n".join(lines)

    def _apply_vault_action(self, action: VaultPanelAction) -> bool:
        kind = action.kind
        if kind == "none":
            if action.hint:
                self._set_status(action.hint)  # type: ignore[attr-defined]
                return True
            return False
        if kind == "move":
            self._update_body_only()  # type: ignore[attr-defined]
            self._vault_sync_table_cursor()
            return True
        if kind == "refresh":
            self._schedule_vault_load()
            self._render_chrome()  # type: ignore[attr-defined]
            return True
        if kind == "intent" and action.intent is not None:
            intent = action.intent
            if intent.risk == "read-only":
                parsed = ParsedCommand(
                    binary=intent.binary, args=tuple(intent.args), display_name=intent.label,
                    category=intent.category, risk="read-only", needs_preview=False,
                )
                self.run_worker(self._run_and_report(parsed), exclusive=False, thread=False)  # type: ignore[attr-defined]
                return True
            self.run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        if kind == "prompt":
            if action.hint:
                self._set_status(action.hint)  # type: ignore[attr-defined]
            self._open_vault_prompt(action.prompt)
            return True
        return False

    def _vault_sync_table_cursor(self) -> None:
        """Move the table highlight to the model's row (j/k move the model; the
        detail line and the highlight must name the same secret)."""
        from textual.widgets import DataTable

        try:
            table = self.query_one("#panel-table", DataTable)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - no table yet (tests, early start)
            return
        with self._programmatic_table_update():  # type: ignore[attr-defined]
            self._position_panel_table_cursor(table, self.vault_model.cursor)  # type: ignore[attr-defined]

    def _open_vault_prompt(self, prompt: str) -> None:
        title, hint, password = self.vault_model.prompt_spec(prompt)

        def done(value: str | None) -> None:
            if value is None:
                self.vault_model.pending_name = self.vault_model.pending_host = ""
                self._set_status("Cancelled; nothing changed.")  # type: ignore[attr-defined]
                return
            self._apply_vault_action(self.vault_model.answer_prompt(prompt, value))

        self.push_screen(FieldEditorScreen(title, hint=hint, password=password), done)  # type: ignore[attr-defined]

    def _vault_command_done(self) -> None:
        self._schedule_vault_load()
