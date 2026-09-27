# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Sandboxes panel behaviour for the Textual TUI (key ``7``).

:class:`SandboxPanelMixin` is mixed into ``DefenseClawTUI``. It owns the
panel's I/O: the periodic REST refresh of ``/api/v1/sandbox/{status,
sandboxes,approvals}`` (keeping the last good snapshot), the live activity
feed (server-sent events on a background thread, resumed by sequence number),
toasts for blocked destinations and new asks, and the actions (unblock,
approve/reject, undo, review, stop, delete). Connect and new runs hand the
terminal to ``defenseclaw-gateway sandbox`` through ``App.suspend`` so the
harness owns it, exactly as on the command line.

The pure state lives in :mod:`defenseclaw.tui.services.sandbox_state`.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any

from rich.markup import escape as rich_escape

from defenseclaw.gateway import SandboxAPIError
from defenseclaw.platform_support import openshell_sandboxes_supported
from defenseclaw.tui.screens.sandbox_detail import SandboxDetailScreen
from defenseclaw.tui.screens.sandbox_launch import (
    SANDBOX_HARNESSES,
    SandboxLaunch,
    SandboxLaunchScreen,
    harness_choices,
    launch_folder_problem,
)
from defenseclaw.tui.services.sandbox_state import (
    ADMIN_MESSAGE,
    VIEW_TITLES,
    SandboxesPanelModel,
    SandboxPanelAction,
    fit,
    review_pairs,
    undo_is_empty,
    undo_preview_text,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction

# Refresh cadence: every tick while the panel is open, every third otherwise.
SANDBOX_POLL_SECONDS = 5.0
SANDBOX_BACKGROUND_EVERY = 3
# Stream reconnect backoff, and the wait after the daemon says sandboxes are off.
STREAM_BACKOFF_MAX = 30.0
STREAM_DISABLED_WAIT = 60.0

_HARNESS_COMMANDS = {"claudecode": "claude", "codex": "codex"}

# Buttons of the panel's control bar, mapped to the key they press.
SANDBOX_BUTTON_KEYS: dict[str, str] = {
    "sandboxes-view": "t",
    "sandboxes-new": "n",
    "sandboxes-connect": "c",
    "sandboxes-stop": "s",
    "sandboxes-delete": "d",
    "sandboxes-undo": "U",
    "sandboxes-review": "R",
    "sandboxes-unblock": "u",
    "sandboxes-approve": "a",
    "sandboxes-always": "A",
    "sandboxes-reject": "x",
    "sandboxes-wrappers": "w",
    "sandboxes-refresh": "r",
    "sandboxes-detail": "enter",
}

# The keys each view's detail window takes (they close it and act on its row).
_DETAIL_KEYS: dict[str, tuple[tuple[str, ...], str]] = {
    "sandboxes": (
        ("c", "s", "d", "U", "R", "u"),
        "Keys: c connect · s stop · d delete · U undo · R review · u unblock · Esc close",
    ),
    "activity": (("u",), "Keys: u unblock · Esc close"),
    "asks": (("a", "A", "x"), "Keys: a approve · A always approve · x reject · Esc close"),
}


@dataclass
class SandboxFetch:
    """One refresh: the three REST reads, or why it failed."""

    status: dict[str, Any] | None = None
    sandboxes: list[dict[str, Any]] | None = None
    approvals: list[dict[str, Any]] | None = None
    error: str = ""
    list_errors: list[str] = field(default_factory=list)


def sandbox_client(config: object | None, *, timeout: int = 3) -> Any | None:
    """An OrchestratorClient for the configured daemon, or None."""
    if config is None:
        return None
    gateway_cfg = getattr(config, "gateway", None)
    if gateway_cfg is None:
        return None
    try:
        port = int(getattr(gateway_cfg, "api_port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if port <= 0:
        return None
    resolve_token = getattr(gateway_cfg, "resolved_token", None)
    token = resolve_token() if callable(resolve_token) else str(getattr(gateway_cfg, "token", "") or "")
    try:
        from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

        host = gateway_api_client_host(config)
    except Exception:  # noqa: BLE001 - a malformed config reads as "no daemon"
        return None
    return OrchestratorClient(host=host, port=port, token=token, timeout=timeout)


def fetch_sandbox_snapshot(config: object | None) -> SandboxFetch:
    """Blocking refresh of status, sandboxes and asks (run in a thread)."""
    client = sandbox_client(config)
    if client is None:
        return SandboxFetch(error="no gateway API port is configured")
    try:
        try:
            status = client.sandbox_status()
        except SandboxAPIError as exc:
            return SandboxFetch(error=exc.plain())
        fetch = SandboxFetch(status=status)
        if not status.get("enabled"):
            fetch.sandboxes, fetch.approvals = [], []
            return fetch
        try:
            fetch.sandboxes = client.list_sandboxes()
        except SandboxAPIError as exc:
            fetch.list_errors.append(exc.plain())
        try:
            fetch.approvals = client.sandbox_approvals()
        except SandboxAPIError as exc:
            fetch.list_errors.append(exc.plain())
        return fetch
    finally:
        client.close()


def _harness_command(name: str) -> str:
    return _HARNESS_COMMANDS.get(name, name)


def probe_sandbox_machine() -> Any:
    """Blocking ``defenseclaw-gateway sandbox doctor --json`` for the Sandbox wizard (run in a thread)."""
    from defenseclaw.commands.cmd_doctor import sandbox_doctor_report
    from defenseclaw.gateway import resolve_gateway_binary
    from defenseclaw.tui.panels.setup import sandbox_machine_check

    binary = resolve_gateway_binary()
    if not binary:
        return sandbox_machine_check(None, "defenseclaw-gateway is not installed (run 'defenseclaw upgrade')")
    report, problem = sandbox_doctor_report(binary)
    return sandbox_machine_check(report, problem)


class SandboxPanelMixin:
    """The Sandboxes panel's polling, streaming, rendering and actions."""

    sandbox_model: SandboxesPanelModel

    # ---- lifecycle --------------------------------------------------------

    def _sandbox_init(self, model: SandboxesPanelModel | None) -> None:
        self._sandbox_model_injected = model is not None
        self.sandbox_model = model or SandboxesPanelModel()
        self.sandbox_model.set_config(getattr(self, "config", None))
        self._sandbox_poll_running = False
        self._sandbox_poll_ticks = 0
        self._sandbox_stream_thread: threading.Thread | None = None
        self._sandbox_stream_stop = threading.Event()
        self._sandbox_stream: Any = None
        self._sandbox_action_running = False
        self._sandbox_machine_checking = False

    def _sandbox_supported(self) -> bool:
        return openshell_sandboxes_supported()

    def _sandbox_mount(self) -> None:
        """Start the periodic refresh (called from on_mount)."""
        if self._sandbox_model_injected or not self._sandbox_supported():
            return
        self.set_interval(SANDBOX_POLL_SECONDS, self._sandbox_poll_tick)  # type: ignore[attr-defined]
        # Hosts that never turned sandboxes on are polled only while the
        # panel is open (switching to it schedules a refresh).
        if self._sandbox_config_enabled():
            self._schedule_sandbox_poll()

    def _sandbox_unmount(self) -> None:
        self._stop_sandbox_stream()

    def _sandbox_config_enabled(self) -> bool:
        openshell = getattr(getattr(self, "config", None), "openshell", None)
        return getattr(openshell, "enabled", False) is True

    def _sandbox_poll_tick(self) -> None:
        self._sandbox_poll_ticks += 1
        active = getattr(self, "active_panel", "") == "sandboxes"
        if not active:
            if not self._sandbox_config_enabled() and not self.sandbox_model.status.enabled:
                return
            if self._sandbox_poll_ticks % SANDBOX_BACKGROUND_EVERY:
                return
        self._schedule_sandbox_poll()

    def _schedule_sandbox_poll(self) -> None:
        if getattr(self, "_app_shutting_down", False) or self._sandbox_model_injected:
            return
        if self._sandbox_poll_running:
            return
        self._sandbox_poll_running = True
        self.run_worker(self._poll_sandbox_once(), exclusive=False, thread=False)  # type: ignore[attr-defined]

    async def _poll_sandbox_once(self) -> None:
        try:
            await self._refresh_sandbox_snapshot(render=getattr(self, "active_panel", "") == "sandboxes")
        finally:
            self._sandbox_poll_running = False

    async def _refresh_sandbox_snapshot(self, *, render: bool) -> None:
        fetch = await asyncio.to_thread(fetch_sandbox_snapshot, getattr(self, "config", None))
        model = self.sandbox_model
        if fetch.status is None:
            model.set_error(fetch.error)
        else:
            model.set_snapshot(fetch.status, fetch.sandboxes, fetch.approvals)
            if fetch.list_errors:
                model.set_error(fetch.list_errors[0])
            if model.status.enabled:
                self._ensure_sandbox_stream()
        if render and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

    # ---- the Sandbox wizard's machine check -------------------------------

    def _schedule_sandbox_machine_check(self) -> None:
        """Run ``sandbox doctor --json`` once the Sandbox wizard opens.

        The form shows "Checking this machine…" meanwhile; the answer sets
        Install OpenShell and the machine row.
        """
        if self._sandbox_machine_checking or getattr(self, "_app_shutting_down", False):
            return
        self._sandbox_machine_checking = True
        self.run_worker(self._check_sandbox_machine(), exclusive=False, thread=False)  # type: ignore[attr-defined]

    async def _check_sandbox_machine(self) -> None:
        try:
            check = await asyncio.to_thread(probe_sandbox_machine)
        except Exception as exc:  # noqa: BLE001 - a failed probe must not break the form
            from defenseclaw.tui.panels.setup import sandbox_machine_check

            check = sandbox_machine_check(None, f"the sandbox doctor failed: {exc}")
        finally:
            self._sandbox_machine_checking = False
        setup_model = getattr(self, "setup_model", None)
        if setup_model is None:
            return
        setup_model.apply_sandbox_machine_check(check)
        if getattr(self, "active_panel", "") == "setup" and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

    # ---- the live feed ----------------------------------------------------

    def _ensure_sandbox_stream(self) -> None:
        if self._sandbox_model_injected or getattr(self, "_app_shutting_down", False):
            return
        thread = self._sandbox_stream_thread
        if thread is not None and thread.is_alive():
            return
        self._sandbox_stream_stop.clear()
        thread = threading.Thread(target=self._sandbox_stream_loop, name="dc-sandbox-activity", daemon=True)
        self._sandbox_stream_thread = thread
        thread.start()

    def _stop_sandbox_stream(self) -> None:
        self._sandbox_stream_stop.set()
        stream = self._sandbox_stream
        if stream is not None:
            try:
                stream.close()
            except Exception:  # noqa: BLE001 - teardown is best effort
                pass

    def _deliver_from_thread(self, callback: Any, *args: Any) -> bool:
        if self._sandbox_stream_stop.is_set() or getattr(self, "_app_shutting_down", False):
            return False
        try:
            self.call_from_thread(callback, *args)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - the app is gone
            return False
        return True

    def _sandbox_stream_loop(self) -> None:
        """Background thread: keep the activity stream open, resuming by seq."""
        backoff = 1.0
        stop = self._sandbox_stream_stop
        while not stop.is_set():
            client = sandbox_client(getattr(self, "config", None), timeout=5)
            if client is None:
                return
            try:
                if self.sandbox_model.last_seq == 0:
                    backlog = client.sandbox_activity()
                    if not self._deliver_from_thread(self._on_sandbox_events, backlog, False):
                        return
                stream = client.open_sandbox_activity_stream(since=self.sandbox_model.last_seq)
                self._sandbox_stream = stream
                if not self._deliver_from_thread(self._set_sandbox_stream_state, "live"):
                    stream.close()
                    return
                backoff = 1.0
                for event in stream:
                    if stop.is_set():
                        break
                    if not self._deliver_from_thread(self._on_sandbox_events, [event], True):
                        return
            except SandboxAPIError as exc:
                if exc.code == "disabled":
                    self._deliver_from_thread(self._set_sandbox_stream_state, "off")
                    return
                self._deliver_from_thread(self._set_sandbox_stream_state, "reconnecting")
            except Exception:  # noqa: BLE001 - a broken stream must never take the TUI down
                self._deliver_from_thread(self._set_sandbox_stream_state, "reconnecting")
            finally:
                self._sandbox_stream = None
                client.close()
            if stop.wait(backoff):
                return
            backoff = min(backoff * 2, STREAM_BACKOFF_MAX)

    def _set_sandbox_stream_state(self, state: str) -> None:
        self.sandbox_model.stream_state = state
        if getattr(self, "active_panel", "") == "sandboxes" and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

    def _on_sandbox_events(self, events: list[dict[str, Any]], toast: bool) -> None:
        # Stream events (toast=True) are live; the one buffered backlog read is not.
        notices = self.sandbox_model.add_events(events, toast=toast, live=toast)
        for notice in notices:
            self.notify_toast(notice.level, notice.message)  # type: ignore[attr-defined]
        if any(event.get("kind") in {"approval.requested", "approval.resolved"} for event in events):
            self._schedule_sandbox_poll()
        if getattr(self, "active_panel", "") == "sandboxes" and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

    # ---- rendering --------------------------------------------------------

    def _sandbox_body_text(self) -> str:
        model = self.sandbox_model
        if not self._sandbox_supported():
            return (
                f"[bold {TOKENS.accent_cyan}]Sandboxes[/]\n\n"
                "OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported."
            )
        state = model.state()
        color = {
            "ready": TOKENS.accent_green,
            "off": TOKENS.text_muted,
            "waiting": TOKENS.accent_blue,
            "unavailable": TOKENS.accent_amber,
            "unreachable": TOKENS.accent_red,
        }[state]
        # A fixed few lines above the table: every per-sandbox detail lives
        # in the table's columns and the Enter detail, so the list and the
        # asks stay on screen at 80x24. The hint bar carries the keys.
        width = self._sandbox_body_width()
        title = f"Sandboxes  ● {state.upper()}  "
        lines = [
            f"[bold {TOKENS.accent_cyan}]Sandboxes[/]  [bold {color}]● {state.upper()}[/]  "
            f"[{TOKENS.text_secondary}]{rich_escape(model.headline(max_width=width - len(title)))}[/]",
        ]
        stale = model.stale_note()
        if stale:
            lines.append(f"[{TOKENS.accent_amber}]{rich_escape(fit(stale, width))}[/]")
        admin = model.admin_line()
        if admin:
            lines.append(f"[{TOKENS.text_secondary}]{rich_escape(fit(admin, width))}[/]")
        views = "  ".join(
            f"[bold reverse] {VIEW_TITLES[view]} [/]"
            if view == model.view
            else f"[{TOKENS.text_muted}]{VIEW_TITLES[view]}[/]"
            for view in VIEW_TITLES
        )
        feed = {"live": "live", "reconnecting": "reconnecting…", "off": "off", "idle": "not connected"}.get(
            model.stream_state, model.stream_state
        )
        plain = f"View:  {'  '.join(f' {VIEW_TITLES[view]} ' for view in VIEW_TITLES)}   feed {feed}"
        view_line = f"View: {views}   [{TOKENS.text_muted}]feed {feed}"
        if model.wrappers or model.harnesses:
            wrapped = " · ".join(
                f"{_harness_command(name)} {'on' if name in model.wrappers else 'off'}"
                for name in (model.harnesses or tuple(name for name, _label in SANDBOX_HARNESSES))
            )
            extra = f"   sandboxed by default: {wrapped} (w)"
            if len(plain) + len(extra) <= width:
                view_line += rich_escape(extra)
        lines.append(view_line + "[/]")
        if model.view == "sandboxes":
            block, where, block_note = model.block_notice()
            alert, alert_note = model.alert_notice()
            for color_notice, text, tail, note in (
                (TOKENS.accent_red, block, where, block_note),
                (TOKENS.accent_amber, alert, "", alert_note),
            ):
                if not text:
                    continue
                suffix = f"  ({note})" if note else ""
                lines.append(
                    f"[{color_notice}]{rich_escape(fit(text, width - len(tail) - len(suffix)))}"
                    f"{rich_escape(tail)}[/][{TOKENS.text_muted}]{rich_escape(suffix)}[/]"
                )
        if not model.data_table_rows():
            empty = model.empty_state()
            if empty:
                lines.append("")
                lines.append(f"[{TOKENS.text_secondary}]{rich_escape(empty)}[/]")
        return "\n".join(lines)

    def _sandbox_body_width(self) -> int:
        """Columns for one header line (the body panel's margin, padding and a scrollbar)."""
        size = getattr(self, "size", None)
        width = int(getattr(size, "width", 0) or 0)
        return max(40, (width or 120) - 8)

    def _sync_sandbox_controls(self) -> None:
        model = self.sandbox_model
        ready = model.state() == "ready"
        selected = model.selected_sandbox()
        view = model.view
        visible = {
            "sandboxes-refresh": True,
            "sandboxes-view": True,
            "sandboxes-new": ready,
            "sandboxes-wrappers": True,
            "sandboxes-connect": ready and selected is not None,
            "sandboxes-stop": ready and selected is not None and selected.running,
            "sandboxes-delete": ready and selected is not None,
            "sandboxes-undo": ready and selected is not None and selected.undo_available,
            "sandboxes-review": ready and selected is not None and selected.workdir_mode != "copy",
            "sandboxes-unblock": ready and self._sandbox_can_unblock(),
            "sandboxes-approve": ready and view == "asks" and model.selected_ask() is not None,
            "sandboxes-always": ready and view == "asks" and model.selected_ask() is not None,
            "sandboxes-reject": ready and view == "asks" and model.selected_ask() is not None,
            "sandboxes-detail": bool(model.data_table_rows()),
        }
        for button_id, show in visible.items():
            self._set_button_visible(f"#{button_id}", show)  # type: ignore[attr-defined]

    def _sandbox_can_unblock(self) -> bool:
        model = self.sandbox_model
        target = model.unblock_target()
        return target is not None and target.unblockable and not model.admin.unblock_refused

    def _handle_sandbox_control(self, button_id: str) -> None:
        key = SANDBOX_BUTTON_KEYS.get(button_id)
        if key is None:
            return
        if button_id == "sandboxes-refresh":
            self._schedule_sandbox_poll()
            self._set_status("Refreshing sandboxes...")  # type: ignore[attr-defined]
            return
        if button_id == "sandboxes-reject" and self.sandbox_model.view != "asks":
            return
        self._apply_sandbox_action(self.sandbox_model.handle_key(key))

    # ---- actions ----------------------------------------------------------

    def _apply_sandbox_action(self, action: SandboxPanelAction) -> bool:
        kind = action.kind
        if kind == "none":
            return False
        if action.hint:
            self._set_status(action.hint)  # type: ignore[attr-defined]
        if kind in {"move", "view"}:
            self._render_chrome()  # type: ignore[attr-defined]
            return True
        if kind == "hint":
            self.notify_toast("info", action.hint)  # type: ignore[attr-defined]
            self._render_chrome()  # type: ignore[attr-defined]
            return True
        if kind == "detail":
            if self.sandbox_model.detail_open:
                self.run_worker(self._open_sandbox_detail(), exclusive=False, thread=False)  # type: ignore[attr-defined]
            else:
                self._render_chrome()  # type: ignore[attr-defined]
            return True
        if kind == "refresh":
            self._set_status("Refreshing sandboxes...")  # type: ignore[attr-defined]
            self._schedule_sandbox_poll()
            return True
        if kind == "new_run":
            self.run_worker(self._sandbox_new_run(), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        if kind == "connect":
            self.run_worker(self._sandbox_connect(action.sandbox), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        if kind == "wrappers":
            self.run_worker(self._sandbox_wrappers_menu(), exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        if self._sandbox_action_running:
            self._set_status("A sandbox action is still running; wait for it to finish.")  # type: ignore[attr-defined]
            return True
        workers = {
            "unblock": lambda: self._sandbox_unblock(action.sandbox, action.host),
            "approve": lambda: self._sandbox_decide(action, approve=True),
            "reject": lambda: self._sandbox_decide(action, approve=False),
            "undo": lambda: self._sandbox_undo(action.sandbox),
            "review": lambda: self._sandbox_review(action.sandbox),
            "stop": lambda: self._sandbox_stop(action.sandbox),
            "delete": lambda: self._sandbox_delete(action.sandbox),
        }
        factory = workers.get(kind)
        if factory is None:
            return False
        self.run_worker(self._guarded_sandbox_action(factory()), exclusive=False, thread=False)  # type: ignore[attr-defined]
        return True

    async def _guarded_sandbox_action(self, coro: Any) -> None:
        self._sandbox_action_running = True
        try:
            await coro
        except SandboxAPIError as exc:
            self._sandbox_report_error(exc)
        except Exception as exc:  # noqa: BLE001 - never a raw stack trace in the TUI
            self.notify_toast("error", f"Sandbox action failed: {exc}")  # type: ignore[attr-defined]
        finally:
            self._sandbox_action_running = False
            self._schedule_sandbox_poll()

    def _sandbox_report_error(self, exc: SandboxAPIError) -> None:
        message = exc.plain()
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("warn" if exc.admin else "error", message)  # type: ignore[attr-defined]

    async def _sandbox_call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        client = sandbox_client(getattr(self, "config", None), timeout=10)
        if client is None:
            raise SandboxAPIError("unavailable", "no gateway API port is configured")
        try:
            return await asyncio.to_thread(getattr(client, method), *args, **kwargs)
        finally:
            client.close()

    async def _confirm(self, title: str, subtitle: str, yes: MenuAction) -> bool:
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(title, (yes, MenuAction("cancel", "Cancel")), subtitle=subtitle)
        )
        return choice == yes.action_id

    async def _open_sandbox_detail(self) -> None:
        model = self.sandbox_model
        title, pairs = model.detail_pairs()
        keys, keys_hint = _DETAIL_KEYS.get(model.view, ((), ""))
        key: str | None = None
        try:
            if pairs:
                key = await self.push_screen_wait(  # type: ignore[attr-defined]
                    SandboxDetailScreen(title, pairs, keys=keys, keys_hint=keys_hint)
                )
        finally:
            model.detail_open = False
            self._render_chrome()  # type: ignore[attr-defined]
        if key:
            # The detail's row is still the selection, so the key acts on it.
            self._apply_sandbox_action(model.handle_key(key))

    async def _sandbox_unblock(self, sandbox: str, host: str) -> None:
        actions = []
        if sandbox:
            actions.append(
                MenuAction("sandbox", f"Only in {sandbox}", "Lifts the block for this sandbox until it is deleted.")
            )
        actions.append(
            MenuAction(
                "always",
                "In every sandbox (always)…",
                "Adds the host to openshell.egress.unblocked (asks first); private networks stay closed.",
            )
        )
        actions.append(MenuAction("cancel", "Cancel"))
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                f"Unblock {host}",
                tuple(actions),
                subtitle="DefenseClaw blocked this destination.",
                show_descriptions=True,
            )
        )
        if choice not in {"sandbox", "always"}:
            self._set_status("Unblock cancelled.")  # type: ignore[attr-defined]
            return
        always = choice == "always"
        if always:
            # As approve-always and the macOS app do: every sandbox, now and
            # later, may reach the host.
            confirmed = await self._confirm(
                f"Unblock {host} in every sandbox?",
                "Every sandbox, now and future, may reach it (openshell.egress.unblocked). "
                "Private networks and this machine stay closed.",
                MenuAction("always", "Unblock everywhere", variant="warning"),
            )
            if not confirmed:
                self._set_status("Unblock cancelled.")  # type: ignore[attr-defined]
                return
        result = await self._sandbox_call(
            "unblock_sandbox_egress", host, sandbox="" if always else sandbox, always=always
        )
        # The daemon's egress.unblocked event says the same; do not wait for it.
        self.sandbox_model.mark_unblocked(sandbox, host, always=always)
        message = str(result.get("message") or f"{host} unblocked")
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    async def _sandbox_decide(self, action: SandboxPanelAction, *, approve: bool) -> None:
        ask = next((ask for ask in self.sandbox_model.asks if ask.id == action.approval_id), None)
        target = ask.destination if ask else action.approval_id
        if approve and action.always:
            confirmed = await self._confirm(
                f"Always allow {target}?",
                "Every future sandbox may reach it too (openshell.egress.unblocked).",
                MenuAction("always", "Always allow", variant="warning"),
            )
            if not confirmed:
                self._set_status("Approval cancelled.")  # type: ignore[attr-defined]
                return
        result = await self._sandbox_call(
            "decide_sandbox_approval", action.approval_id, approve=approve, always=action.always
        )
        message = str(result.get("message") or "")
        if not message:
            verb = "approved" if approve else "rejected"
            message = f"{target} {verb}" + (" (applies when the agent is idle)" if approve else "")
        self.sandbox_model.asks = tuple(a for a in self.sandbox_model.asks if a.id != action.approval_id)
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    async def _sandbox_undo(self, name: str) -> None:
        preview = await self._sandbox_call("undo_sandbox", name, preview=True, stop=False)
        if undo_is_empty(preview):
            message = f"Nothing to undo: {name}'s folder matches its pre-session snapshot."
            self._set_status(message)  # type: ignore[attr-defined]
            self.notify_toast("info", message)  # type: ignore[attr-defined]
            return
        row = next((row for row in self.sandbox_model.rows if row.name == name), None)
        stops = " (it stops the sandbox first)" if row is not None and row.running else ""
        confirmed = await self._confirm(
            f"Undo {name}?",
            f"Puts the project folder back to its pre-session snapshot{stops}. " + undo_preview_text(preview),
            MenuAction("undo", "Undo everything", variant="warning"),
        )
        if not confirmed:
            self._set_status("Undo cancelled; nothing changed.")  # type: ignore[attr-defined]
            return
        result = await self._sandbox_call("undo_sandbox", name, stop=True)
        message = str(result.get("summary") or f"{name}: the project folder is back to its snapshot")
        if result.get("stopped"):
            message += f"; {name} is stopped (c to resume)"
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    async def _sandbox_review(self, name: str) -> None:
        self._set_status(f"Reviewing {name}...")  # type: ignore[attr-defined]
        result = await self._sandbox_call("review_sandbox", name)
        await self.push_screen_wait(  # type: ignore[attr-defined]
            SandboxDetailScreen(
                f"Review {name}",
                review_pairs(result),
                keys_hint="Up/Down and PageUp/PageDown scroll · Esc close",
            )
        )

    async def _sandbox_stop(self, name: str) -> None:
        confirmed = await self._confirm(
            f"Stop {name}?",
            "Ends the harness session running in it. The sandbox is kept: connect (c) resumes it.",
            MenuAction("stop", "Stop", variant="warning"),
        )
        if not confirmed:
            self._set_status("Stop cancelled.")  # type: ignore[attr-defined]
            return
        self._set_status(f"Stopping {name}...")  # type: ignore[attr-defined]
        await self._sandbox_call("stop_sandbox", name)
        message = f"{name} stopped; it is kept for connect (c)"
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    async def _sandbox_delete(self, name: str) -> None:
        confirmed = await self._confirm(
            f"Delete {name}?",
            "Deletes the sandbox with its providers, credentials and snapshot (undo is no longer possible). "
            "Your project folder keeps its current contents.",
            MenuAction("delete", "Delete", variant="error"),
        )
        if not confirmed:
            self._set_status("Delete cancelled.")  # type: ignore[attr-defined]
            return
        result = await self._sandbox_call("delete_sandbox", name)
        message = f"{name} deleted"
        warnings = [str(w) for w in result.get("warnings") or [] if w]
        if warnings:
            message += f" ({warnings[0]})"
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    async def _sandbox_wrappers_menu(self) -> None:
        model = self.sandbox_model
        names = model.harnesses or tuple(name for name, _label in SANDBOX_HARNESSES)
        actions = []
        for name in names:
            command = _harness_command(name)
            on = name in model.wrappers
            actions.append(
                MenuAction(
                    name,
                    f"`{command}` sandboxed: {'on' if on else 'off'}",
                    f"Turn {'off' if on else 'on'}: defenseclaw sandbox {'disable' if on else 'enable'} {command}",
                )
            )
        actions.append(MenuAction("cancel", "Cancel"))
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                "Sandboxed by default",
                tuple(actions),
                subtitle="A marked block in your shell rc makes the command run sandboxed "
                "(DEFENSECLAW_NO_SANDBOX=1 bypasses once).",
                show_descriptions=True,
            )
        )
        if choice in (None, "cancel"):
            return
        verb = "disable" if choice in model.wrappers else "enable"
        command = _harness_command(choice)
        await self._run_command(  # type: ignore[attr-defined]
            "defenseclaw", ("sandbox", verb, command), display_name=f"sandbox {verb} {command}"
        )

    async def _sandbox_new_run(self) -> None:
        if not self._sandbox_supported():
            self._set_status("OpenShell sandboxes run on Linux and macOS only.")  # type: ignore[attr-defined]
            return
        model = self.sandbox_model
        if model.state() == "off":
            self.notify_toast("info", "Sandboxes are off; run the Sandbox wizard (0 Setup) first.")  # type: ignore[attr-defined]
            return
        choices = harness_choices(model.harnesses, model.admin.allowed_harnesses)
        if not choices:
            self.notify_toast("warn", f"No harness may run: {ADMIN_MESSAGE}.")  # type: ignore[attr-defined]
            return
        launch = await self.push_screen_wait(  # type: ignore[attr-defined]
            SandboxLaunchScreen(choices, folder=self._sandbox_default_folder())
        )
        if launch is None:
            self._set_status("New run cancelled.")  # type: ignore[attr-defined]
            return
        self._run_sandbox_terminal(launch)

    def _sandbox_default_folder(self) -> str:
        """The launch dialog's folder: the selected, else the newest, sandbox's project.

        The TUI's own folder only when it could be a project (it is often the
        home folder, which a run refuses).
        """
        model = self.sandbox_model
        selected = model.selected_sandbox()
        newest = sorted(
            (row for row in model.rows if row.project),
            key=lambda row: row.created_at.timestamp() if row.created_at else 0.0,
            reverse=True,
        )
        for row in ([selected] if selected is not None else []) + newest:
            if row.project and os.path.isdir(row.project):
                return row.project
        cwd = os.getcwd()
        return "" if launch_folder_problem(cwd) else cwd

    async def _sandbox_connect(self, name: str) -> None:
        launch = SandboxLaunch(("sandbox", "connect", name), os.getcwd(), f"sandbox connect {name}")
        self._run_sandbox_terminal(launch)

    def _run_sandbox_terminal(self, launch: SandboxLaunch, *, notify_unsupported: bool = True) -> int | None:
        """Hand the terminal to ``defenseclaw-gateway`` and return its exit status.

        ``None`` when the terminal cannot be handed over (no gateway binary,
        or an environment Textual cannot suspend).
        """
        from textual.app import SuspendNotSupported

        from defenseclaw.gateway import resolve_gateway_binary

        binary = resolve_gateway_binary()
        command = "defenseclaw " + " ".join(launch.argv)
        if not binary:
            self.notify_toast("error", "defenseclaw-gateway is not installed; run 'defenseclaw upgrade'.")  # type: ignore[attr-defined]
            return None
        returncode = 0
        try:
            with self.suspend():  # type: ignore[attr-defined]
                print(f"\n→ {command}   (the TUI comes back when it ends)\n", flush=True)
                try:
                    returncode = subprocess.run([binary, *launch.argv], cwd=launch.cwd, check=False).returncode
                except OSError as exc:
                    print(f"could not start {binary}: {exc}", flush=True)
                    returncode = 127
                except KeyboardInterrupt:
                    returncode = 130
                # Keep the session summary on screen until the operator is done reading.
                try:
                    input("\nPress Enter to return to DefenseClaw... ")
                except (EOFError, KeyboardInterrupt, OSError):
                    pass
        except SuspendNotSupported:
            if notify_unsupported:
                self.notify_toast(  # type: ignore[attr-defined]
                    "warn", f"This terminal cannot be handed over; run it in a shell: cd {launch.cwd} && {command}"
                )
            return None
        self._schedule_sandbox_poll()
        if returncode:
            self._set_status(f"{command} exited {returncode}")  # type: ignore[attr-defined]
        else:
            self._set_status(f"{launch.display}: finished")  # type: ignore[attr-defined]
        self._render_chrome()  # type: ignore[attr-defined]
        return returncode

    async def _confirm_and_run_terminal_intent(self, intent: Any) -> None:
        """Preview a setup intent, then run it in the real terminal."""
        from defenseclaw.tui.command_line import ParsedCommand
        from defenseclaw.tui.screens.command_preview import CommandPreviewScreen

        args = tuple(intent.args)
        parsed = ParsedCommand(
            binary=intent.binary,
            args=args,
            display_name=intent.label,
            category=intent.category,
            risk="setup",
            needs_preview=True,
        )
        confirmed = await self.push_screen_wait(CommandPreviewScreen(parsed))  # type: ignore[attr-defined]
        setup_model = getattr(self, "setup_model", None)
        if not confirmed:
            if setup_model is not None:
                setup_model.mark_wizard_complete(args, success=False)
            self._set_status("Command cancelled.")  # type: ignore[attr-defined]
            self._render_chrome()  # type: ignore[attr-defined]
            return
        returncode = self._run_sandbox_terminal(
            SandboxLaunch(args, os.getcwd(), intent.label), notify_unsupported=False
        )
        if returncode is None:
            # No terminal to hand over: run it captured, with its prompts in Activity.
            await self._run_command(intent.binary, args, display_name=intent.label)  # type: ignore[attr-defined]
            return
        if setup_model is not None:
            setup_model.mark_wizard_complete(args, success=returncode == 0)
        if returncode == 0:
            refresh = getattr(self, "_refresh_cached_config", None)
            if callable(refresh):
                refresh()
            self.notify_toast("success", f"{intent.label} finished")  # type: ignore[attr-defined]
        else:
            self.notify_toast(  # type: ignore[attr-defined]
                "error", f"{intent.label} exited {returncode}; check this machine with: defenseclaw sandbox doctor"
            )
        self._render_chrome()  # type: ignore[attr-defined]
