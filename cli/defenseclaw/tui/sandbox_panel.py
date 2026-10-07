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
approve/reject, undo, review, pull, stop, delete). Connect and new runs hand
the terminal to ``defenseclaw-gateway sandbox`` through ``App.suspend`` so the
harness owns it, exactly as on the command line. So do stop, delete, pull and
the undo of a running or copy-mode sandbox: the command line asks about what
they end or discard (a detached run still going, copy-mode work never pulled
back) and does work on this machine before it calls the daemon (what a copy
held as it stopped, the git work of a pull and of its revert, its own state
for a deleted sandbox). The daemon's stop, whoever asks for it, marks a
detached run it ends interrupted and keeps its log for ``sandbox logs``.

The pure state lives in :mod:`defenseclaw.tui.services.sandbox_state`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from typing import Any

from textual import events

from defenseclaw.gateway import SandboxAPIError
from defenseclaw.platform_support import openshell_sandboxes_supported
from defenseclaw.tui.markup_safe import escape as rich_escape
from defenseclaw.tui.screens.sandbox_detail import SandboxDetailScreen
from defenseclaw.tui.screens.sandbox_launch import (
    SandboxLaunch,
    SandboxLaunchScreen,
    harness_choices,
    launch_folder_problem,
)
from defenseclaw.tui.services.sandbox_state import (
    ADMIN_MESSAGE,
    DEFAULT_SANDBOX_HARNESSES,
    VIEW_TITLES,
    SandboxesPanelModel,
    SandboxPanelAction,
    fit,
    harness_command,
    review_pairs,
    undo_done_text,
    undo_is_empty,
    undo_preview_text,
    undo_unrestored,
    undo_unrestored_lines,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction

# Refresh cadence: every tick while the panel is open, every third otherwise.
SANDBOX_POLL_SECONDS = 5.0
SANDBOX_BACKGROUND_EVERY = 3
# Stream reconnect backoff, and the wait after the daemon says sandboxes are off.
STREAM_BACKOFF_MAX = 30.0
STREAM_DISABLED_WAIT = 60.0
# Under this many columns the panel drops its button bar: the KEYS line
# names the same keys, and the rows need the room.
SANDBOX_BUTTON_BAR_MIN_WIDTH = 100

# Buttons of the panel's control bar, mapped to the key they press.
SANDBOX_BUTTON_KEYS: dict[str, str] = {
    "sandboxes-view": "t",
    "sandboxes-new": "n",
    "sandboxes-connect": "c",
    "sandboxes-stop": "s",
    "sandboxes-delete": "d",
    "sandboxes-undo": "U",
    "sandboxes-review": "R",
    "sandboxes-pull": "P",
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
    # A sandbox that works on a copy: pull brings its work back.
    "copy": (
        ("c", "s", "d", "U", "P", "u"),
        "Keys: c connect · s stop · d delete · U undo · P pull · u unblock · Esc close",
    ),
    "activity": (("u",), "Keys: u unblock · Esc close"),
    "asks": (("a", "A", "x"), "Keys: a approve · A always approve · x reject · Esc close"),
}


class _PromptInterruptedError(Exception):
    """Ctrl-C at the "Press Enter" prompt: back to the TUI."""


class _HandoverCtrlC:
    """The SIGINT handler while a child owns the terminal.

    A Python handler rather than SIG_IGN, so the child still gets the
    default one (exec resets it). Ctrl-C does nothing in the TUI, except at
    the "Press Enter" prompt (``at_prompt``), which it ends.
    """

    def __init__(self) -> None:
        self.at_prompt = False

    def __call__(self, _signum: int, _frame: Any) -> None:
        if self.at_prompt:
            self.at_prompt = False
            raise _PromptInterruptedError


@contextlib.contextmanager
def _child_owns_ctrl_c() -> Iterator[_HandoverCtrlC]:
    """Keep the TUI's own SIGINT handler away while a child runs in the terminal.

    The TUI shares the terminal's foreground process group with the child,
    so a Ctrl-C meant for the child's prompt reaches the TUI as well, and
    asyncio's handler cancels the app's main task on the first one: the TUI
    quit silently once the child ended, and the next keys went to the shell.
    """
    handler = _HandoverCtrlC()
    if threading.current_thread() is not threading.main_thread():
        yield handler
        return
    try:
        previous = signal.signal(signal.SIGINT, handler)
    except (ValueError, OSError):
        yield handler
        return
    try:
        yield handler
    finally:
        handler.at_prompt = False
        # None: the handler was not installed from Python; Python's own is the closest.
        signal.signal(signal.SIGINT, previous if previous is not None else signal.default_int_handler)


def _drop_pending_input() -> None:
    """Discard keys typed while the child had the terminal (a stray Ctrl-C would quit the TUI)."""
    try:
        import termios

        if sys.stdin is not None and sys.stdin.isatty():
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except (ImportError, OSError, ValueError):
        pass


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


def fetch_sandbox_processes(config: object | None, name: str) -> dict[str, Any] | None:
    """Blocking read of a sandbox's process tree (run in a thread); None when it fails."""
    client = sandbox_client(config)
    if client is None:
        return None
    try:
        return client.sandbox_processes(name)
    except SandboxAPIError:
        return None
    finally:
        client.close()


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
                resume = self.sandbox_model.last_seq
                if resume:
                    # Read from one event early: a daemon that restarted
                    # numbers its events from one again, and resuming after
                    # the old number would skip its first events.
                    probe = client.sandbox_activity(since=resume - 1)
                    if not self._deliver_from_thread(self._on_sandbox_resume, probe):
                        return
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

    def _on_sandbox_resume(self, probe: list[dict[str, Any]]) -> None:
        """Start the feed over when the daemon's no longer holds the resume point.

        The stream loop then reads the new daemon's backlog (without toasts,
        as at start) and follows from its end.
        """
        if self.sandbox_model.resume_point_lost(probe):
            self.sandbox_model.reset_resume_point()

    def _on_sandbox_events(self, events: list[dict[str, Any]], toast: bool) -> None:
        # Stream events (toast=True) are live; the one buffered backlog read is not.
        notices = self.sandbox_model.add_events(events, toast=toast, live=toast)
        for notice in notices:
            self.notify_toast(notice.level, notice.message)  # type: ignore[attr-defined]
        if any(
            event.get("kind") in {"approval.requested", "approval.resolved"}
            or (event.get("kind") == "finding" and event.get("reason") == "hook_tamper")
            for event in events
        ):
            # The list's asks and its tamper count change with these.
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
                f"{harness_command(name)} {'on' if name in model.wrappers else 'off'}"
                for name in (model.harnesses or DEFAULT_SANDBOX_HARNESSES)
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

    def _sandbox_button_bar_collapsed(self) -> bool:
        """Whether the terminal is too narrow for the button bar (the KEYS line stays)."""
        width = int(getattr(getattr(self, "size", None), "width", 0) or 0)
        return 0 < width < SANDBOX_BUTTON_BAR_MIN_WIDTH

    def on_resize(self, _event: events.Resize) -> None:
        # The table's columns and the button bar follow the width, once the
        # app has taken the new size.
        if getattr(self, "active_panel", "") != "sandboxes" or getattr(self, "help_open", False):
            return
        self.call_after_refresh(self._render_sandbox_after_resize)  # type: ignore[attr-defined]

    def _render_sandbox_after_resize(self) -> None:
        from textual.css.query import NoMatches

        if getattr(self, "active_panel", "") != "sandboxes":
            return
        try:
            self._render_chrome()  # type: ignore[attr-defined]
        except NoMatches:
            pass

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
        # Row buttons for a sandbox only on the Sandboxes view: in Asks they
        # filled the bar and pushed Approve / Always / Reject off an
        # 80-column screen.
        row = ready and selected is not None and view == "sandboxes"
        visible = {
            "sandboxes-refresh": True,
            "sandboxes-view": True,
            "sandboxes-new": ready,
            "sandboxes-wrappers": True,
            "sandboxes-connect": row,
            "sandboxes-stop": row and selected.running,
            "sandboxes-delete": row,
            # A copy's undo reverts its last pull --apply: it needs no snapshot.
            "sandboxes-undo": row and (selected.undo_available or selected.copy_mode),
            "sandboxes-review": row and not selected.copy_mode,
            "sandboxes-pull": row and selected.copy_mode,
            "sandboxes-unblock": ready and self._sandbox_can_unblock(),
            "sandboxes-approve": ready and view == "asks" and model.selected_ask() is not None,
            # Private, IP-literal and host-local asks open for one sandbox only.
            "sandboxes-always": ready and view == "asks" and model.always_offered(),
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
            "pull": lambda: self._sandbox_pull(action.sandbox),
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

    async def _confirm(self, title: str, subtitle: str, yes: MenuAction, *, cancel_first: bool = False) -> bool:
        """Ask before an action; ``cancel_first`` focuses Cancel (irreversible or permanent actions)."""
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                title,
                (yes, MenuAction("cancel", "Cancel")),
                subtitle=subtitle,
                selected_index=1 if cancel_first else None,
            )
        )
        return choice == yes.action_id

    def _sandbox_detail_keys(self) -> tuple[tuple[str, ...], str]:
        """The keys the detail window offers for the selected row."""
        model = self.sandbox_model
        keys, keys_hint = _DETAIL_KEYS.get(model.view, ((), ""))
        selected = model.selected_sandbox()
        if model.view == "sandboxes" and selected is not None and selected.copy_mode:
            keys, keys_hint = _DETAIL_KEYS["copy"]
        if model.view == "activity" and not model.unblock_offered():
            # A tool block, an allowed or lifted destination: u does nothing here.
            return (), "Keys: Esc close"
        if model.view == "asks" and not model.always_offered():
            return ("a", "x"), "Keys: a approve once · x reject · Esc close"
        return keys, keys_hint

    async def _open_sandbox_detail(self) -> None:
        model = self.sandbox_model
        selected = model.selected_sandbox() if model.view == "sandboxes" else None
        if selected is not None and selected.process_tree:
            # A stopped sandbox has no live processes, and a failed fetch has
            # none to show: the last tree is never shown as current.
            payload = None
            if selected.running:
                payload = await asyncio.to_thread(fetch_sandbox_processes, getattr(self, "config", None), selected.name)
            model.set_processes(selected.name, payload)
        title, pairs = model.detail_pairs()
        keys, keys_hint = self._sandbox_detail_keys()
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
            # The selection follows its item through the refreshes that ran
            # while the detail was open, so the key acts on the item shown;
            # the model refuses it when that item went away meanwhile.
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
        # Say why it was blocked, so the user knows what the unblock lifts.
        why = self.sandbox_model.block_explanation(sandbox, host)
        subtitle = f"DefenseClaw blocked this destination: {why}" if why else "DefenseClaw blocked this destination."
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                f"Unblock {host}",
                tuple(actions),
                subtitle=subtitle,
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
                cancel_first=True,
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
            if ask is not None and ask.always_refusal:
                # The daemon refuses it too; never ask to confirm what cannot be done.
                message = f"No always for {target}: {ask.always_refusal}; press a to approve once."
                self._set_status(message)  # type: ignore[attr-defined]
                self.notify_toast("warn", message)  # type: ignore[attr-defined]
                return
            confirmed = await self._confirm(
                f"Always allow {target}?",
                "Every future sandbox may reach it too (openshell.egress.unblocked).",
                MenuAction("always", "Always allow", variant="warning"),
                cancel_first=True,
            )
            if not confirmed:
                self._set_status("Approval cancelled.")  # type: ignore[attr-defined]
                return
        result = await self._sandbox_call(
            "decide_sandbox_approval", action.approval_id, approve=approve, always=action.always
        )
        message = str(result.get("message") or "")
        if approve and action.always:
            # The daemon's message is the one-time approve's; say what was saved.
            saved = " (saved to openshell.egress.unblocked)" if result.get("persisted") else ""
            message = f"always allowed {target}{saved}" + (f"; {message}" if message else "")
        elif not message:
            verb = "approved" if approve else "rejected"
            message = f"{target} {verb}" + (" (applies when the agent is idle)" if approve else "")
        self.sandbox_model.remove_ask(action.approval_id)
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("success", message)  # type: ignore[attr-defined]

    def _run_sandbox_cli(self, *argv: str) -> None:
        """Run ``defenseclaw sandbox ...`` in the terminal, where it asks what it needs to.

        Stop, delete and the undo of a running sandbox look at the sandbox
        before they call the daemon: they ask while a detached run the stop
        would end is still going, look for copy-mode work that was never
        pulled back (and remember what a copy held as it stopped), and
        forget what the command line kept for a deleted sandbox. The
        daemon's stop marks the run interrupted and keeps its log for
        ``sandbox logs``.
        """
        self._run_sandbox_terminal(SandboxLaunch(("sandbox", *argv), os.getcwd(), "sandbox " + " ".join(argv)))

    async def _sandbox_undo(self, name: str) -> None:
        row = next((row for row in self.sandbox_model.rows if row.name == name), None)
        if row is not None and row.copy_mode:
            # A copy's undo reverts its last `pull --apply` with git in the
            # project folder, on this machine: the command line previews the
            # revert and asks, or says there is none to revert.
            self._run_sandbox_cli("undo", name)
            return
        if row is not None and row.running:
            # Undo stops the sandbox first: the command line previews, says
            # what the stop ends (a detached run too) and asks.
            self._run_sandbox_cli("undo", name)
            return
        preview = await self._sandbox_call("undo_sandbox", name, preview=True, stop=False)
        unrestored = undo_unrestored_lines(preview)
        if undo_is_empty(preview):
            if unrestored:
                await self._show_unrestored(name, preview)
                return
            message = f"Nothing to undo: {name}'s folder matches its pre-session snapshot."
            self._set_status(message)  # type: ignore[attr-defined]
            self.notify_toast("info", message)  # type: ignore[attr-defined]
            return
        confirmed = await self._confirm(
            f"Undo {name}?",
            # Paths come from the sandbox: no markup. The menu does not
            # scroll, so it names the first few places undo cannot restore.
            rich_escape(
                "Puts the project folder back to its pre-session snapshot.\n"
                + undo_preview_text(preview, unrestored_limit=3)
            ),
            MenuAction("undo", "Undo everything", variant="warning"),
            cancel_first=True,
        )
        if not confirmed:
            self._set_status("Undo cancelled; nothing changed.")  # type: ignore[attr-defined]
            return
        # Not stop=True: a sandbox that started meanwhile is refused (stop it
        # with s, which asks about a detached run first) rather than stopped here.
        result = await self._sandbox_call("undo_sandbox", name, stop=False)
        message = undo_done_text(result, name)
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("warn" if undo_unrestored(result) else "success", message)  # type: ignore[attr-defined]

    async def _show_unrestored(self, name: str, preview: Any) -> None:
        """Undo has nothing to put back, but the session changed what it cannot restore."""
        lines = undo_unrestored_lines(preview)
        places = len(undo_unrestored(preview))
        message = (
            f"Nothing else to undo in {name}, but undo cannot restore {places} place(s) the session changed; "
            "they are listed."
        )
        self._set_status(message)  # type: ignore[attr-defined]
        self.notify_toast("warn", message)  # type: ignore[attr-defined]
        pairs = [("Undo", f"nothing else to undo: the rest of {name}'s folder matches its pre-session snapshot")]
        pairs.extend(("Not restored", line.removeprefix("undo cannot restore ")) for line in lines)
        await self.push_screen_wait(  # type: ignore[attr-defined]
            SandboxDetailScreen(f"Undo {name}", tuple(pairs), keys_hint="Esc close")
        )

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

    async def _sandbox_pull(self, name: str) -> None:
        """Bring a copy-mode sandbox's work back through ``defenseclaw sandbox pull``.

        The command line reads the work, scans it (secrets, changes that can
        run code on this machine) and prints it before it applies anything,
        and asks before it brings back what can run code here. A stopped
        sandbox is started to read its work and stopped again.
        """
        row = next((row for row in self.sandbox_model.rows if row.name == name), None)
        project = row.project if row is not None and row.project else "your project folder"
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                f"Pull {name}'s work",
                (
                    MenuAction("review", "Show what comes back", f"Changes nothing: defenseclaw sandbox pull {name}"),
                    MenuAction(
                        "apply",
                        "Apply it to the project folder",
                        "Merges it into your working tree (3-way; a conflict leaves the tree alone), "
                        f"and U reverts it: defenseclaw sandbox pull {name} --apply",
                    ),
                    MenuAction(
                        "branch",
                        f"Put it on branch dc/{name}",
                        f"Your working tree stays as it is: defenseclaw sandbox pull {name} --branch",
                    ),
                    MenuAction("cancel", "Cancel"),
                ),
                # The menu shows the subtitle as plain text: the path needs no escaping.
                subtitle=f"{name} works on a copy of {project}. Pull shows the changes first, and asks before "
                "it brings back a change that can run code on this machine.",
                show_descriptions=True,
            )
        )
        flags = {"review": (), "apply": ("--apply",), "branch": ("--branch",)}.get(choice or "")
        if flags is None:
            self._set_status("Pull cancelled; nothing changed.")  # type: ignore[attr-defined]
            return
        self._run_sandbox_cli("pull", name, *flags)

    async def _sandbox_stop(self, name: str) -> None:
        confirmed = await self._confirm(
            f"Stop {name}?",
            "Ends the harness session running in it. A detached run (sandbox run --detach) still going ends "
            "unfinished: `defenseclaw sandbox stop` runs in this terminal and asks first when one is, and "
            f"DefenseClaw keeps its log for `defenseclaw sandbox logs {name}`. The sandbox is kept: connect (c) "
            "resumes it.",
            MenuAction("stop", "Stop", variant="warning"),
        )
        if not confirmed:
            self._set_status("Stop cancelled.")  # type: ignore[attr-defined]
            return
        self._run_sandbox_cli("stop", name)

    async def _sandbox_delete(self, name: str) -> bool:
        """Delete ``name`` through the command line, which asks; whether it is gone.

        For a copy-mode sandbox the command line first looks for work that
        never came back to the folder (never pulled, or pulled and not
        applied), which deleting it discards.
        """
        code = self._run_sandbox_terminal(
            SandboxLaunch(("sandbox", "delete", name), os.getcwd(), f"sandbox delete {name}")
        )
        if code != 0:
            return False
        await self._refresh_sandbox_snapshot(render=False)
        return all(row.name != name for row in self.sandbox_model.rows)

    async def _sandbox_wrappers_menu(self) -> None:
        if not self._sandbox_supported():
            # The menu offered "Turn on: defenseclaw sandbox enable claude" on
            # Windows, which the command refuses (GAP-1328); say it like n/t do.
            self._set_status("OpenShell sandboxes run on Linux and macOS only.")  # type: ignore[attr-defined]
            return
        model = self.sandbox_model
        names = model.harnesses or DEFAULT_SANDBOX_HARNESSES
        # A wrapper runs `sandbox run`, so while sandboxes cannot run the
        # plain command would fail in every new shell; enable refuses then.
        blocked = {
            "off": "Sandboxes are off; run the Sandbox wizard (0 Setup) first",
            "unavailable": "Sandboxes are unavailable; see: defenseclaw sandbox doctor",
            # Before the first snapshot the state is unknown; offering "Turn
            # on" then ran an enable the command refused (GAP-1371).
            "waiting": "Sandbox status is still loading; try again in a moment",
            "unreachable": "The DefenseClaw daemon is not answering; check: defenseclaw sandbox doctor",
        }.get(model.state(), "")
        actions = []
        for name in names:
            command = harness_command(name)
            on = name in model.wrappers
            hint = f"Turn {'off' if on else 'on'}: defenseclaw sandbox {'disable' if on else 'enable'} {command}"
            if blocked and not on:
                hint = blocked
            actions.append(MenuAction(name, f"`{command}` sandboxed: {'on' if on else 'off'}", hint))
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
        if verb == "enable" and blocked:
            self.notify_toast("info", f"{blocked}.")  # type: ignore[attr-defined]
            return
        command = harness_command(choice)
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
            SandboxLaunchScreen(choices, folder=self._sandbox_default_folder(), copy_only=model.status.copy_only_note)
        )
        if launch is None:
            self._set_status("New run cancelled.")  # type: ignore[attr-defined]
            return
        launch = await self._resolve_live_mount(launch)
        if launch is not None:
            self._run_sandbox_terminal(launch)

    async def _resolve_live_mount(self, launch: SandboxLaunch) -> SandboxLaunch | None:
        """Offer a copy, the sandbox already there, or deleting it, when it mounts the folder live.

        A folder takes one live mount (two would each undo the other's work),
        so the daemon would refuse this run; ``sandbox run`` asks the same on
        a terminal. None when nothing should start here.
        """
        if "--copy" in launch.argv:
            return launch
        holder = self.sandbox_model.live_mount_holder(launch.cwd)
        if holder is None:
            return launch
        name = holder.name
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            ActionMenuScreen(
                f"{name} already mounts this folder live",
                (
                    MenuAction(
                        "copy",
                        "Run this one on a copy (--copy)",
                        "defenseclaw sandbox pull brings its changes back to the folder.",
                    ),
                    MenuAction(
                        "connect",
                        f"Connect {name} instead",
                        f"Resumes {name} ({holder.harness_label}, {holder.phase or '-'}): "
                        f"defenseclaw sandbox connect {name}",
                    ),
                    MenuAction(
                        "delete",
                        f"Delete {name} first…",
                        f"Asks first, then this run mounts the folder: defenseclaw sandbox delete {name}",
                    ),
                    MenuAction("cancel", "Cancel"),
                ),
                subtitle=f"{holder.project} takes one live mount: two would each undo the other's work.",
                show_descriptions=True,
            )
        )
        if choice == "copy":
            return replace(launch, argv=(*launch.argv, "--copy"))
        if choice == "connect":
            await self._sandbox_connect(name)
            return None
        if choice == "delete":
            try:
                deleted = await self._sandbox_delete(name)
            except SandboxAPIError as exc:
                self._sandbox_report_error(exc)
                return None
            finally:
                self._schedule_sandbox_poll()
            return launch if deleted else None
        self._set_status(f"New run cancelled; {name} still mounts {holder.project} live.")  # type: ignore[attr-defined]
        return None

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
                # Ctrl-C belongs to the child (its keep prompt, say); at the
                # "Press Enter" prompt it returns to the TUI.
                with _child_owns_ctrl_c() as ctrl_c:
                    try:
                        print(f"\n→ {command}   (the TUI comes back when it ends)\n", flush=True)
                        try:
                            returncode = subprocess.run([binary, *launch.argv], cwd=launch.cwd, check=False).returncode
                        except OSError as exc:
                            print(f"could not start {binary}: {exc}", flush=True)
                            returncode = 127
                        except KeyboardInterrupt:
                            returncode = 130
                        # Keep the session summary on screen until the operator is done reading.
                        ctrl_c.at_prompt = True
                        try:
                            input("\nPress Enter to return to DefenseClaw... ")
                        finally:
                            ctrl_c.at_prompt = False
                    except (EOFError, KeyboardInterrupt, OSError, _PromptInterruptedError):
                        pass
                    _drop_pending_input()
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
                setup_model.mark_wizard_complete(args, success=False, cancelled=True)
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
