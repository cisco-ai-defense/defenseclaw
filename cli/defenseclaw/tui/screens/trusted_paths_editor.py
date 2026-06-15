# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native Setup editor for trusted binary-discovery prefixes.

Mutations dismiss with a ``SetupResourceResult`` carrying ``defenseclaw setup
trusted-paths add|remove`` argv, which the app runs through the same
command-preview + execute path as the Webhooks/Audit-Sinks editors. That keeps
a single persistence path (the CLI) shared by the TUI, the inline setup prompt,
and the discovery gate — they can't drift, and the preview screen surfaces the
exact command (and therefore the security implication) before it runs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

from defenseclaw.tui.screens.setup_resource_editor import SetupResourceResult
from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS


@dataclass(frozen=True)
class TrustedPathRow:
    """One trusted-prefix row for the editor table."""

    resolved: str
    source: str
    status: str
    removable: bool


class TrustedPathsEditorScreen(ModalScreen[SetupResourceResult | None]):
    """Rounded native editor for the trusted binary-prefix allow-list."""

    CSS = f"""
    TrustedPathsEditorScreen {{
        align: center middle;
    }}

    #trusted-editor-dialog {{
        width: 116;
        height: 32;
        padding: 1 2;
        border: round {TOKENS.border_active};
        background: {TOKENS.surface_panel};
        color: {TOKENS.text_primary};
    }}

    #trusted-editor-title {{
        height: 1;
        margin-bottom: 1;
        color: {TOKENS.accent_cyan};
        text-style: bold;
    }}

    #trusted-editor-table {{
        height: 16;
        margin-bottom: 1;
    }}

    #trusted-editor-add {{
        height: 3;
        margin-bottom: 1;
    }}

    #trusted-editor-status {{
        height: 2;
        color: {TOKENS.text_secondary};
    }}

    #trusted-editor-buttons {{
        height: 3;
        align-horizontal: right;
    }}

    #trusted-editor-buttons Button {{
        margin-left: 1;
    }}
    """

    BINDINGS = [
        # Letter keys are reserved for the directory Input, so removal/close
        # use non-text keys that can't collide with typing a path.
        Binding("escape", "cancel", "Close", show=False),
        Binding("delete", "remove", "Remove", show=False),
    ]

    def __init__(
        self,
        rows: tuple[TrustedPathRow, ...],
        *,
        prefill: str = "",
        context: str = "",
        data_dir: str | None = None,
    ) -> None:
        super().__init__()
        self.rows = tuple(rows)
        self.cursor = 0
        # When the editor is opened by routing an untrusted-binary setup into
        # it, ``prefill`` seeds the add field with the offending directory and
        # ``context`` explains why the operator landed here.
        # NOTE: store as ``_context_text`` — ``_context`` is reserved by
        # Textual's ``MessagePump`` (a callable used as ``with self._context():``
        # in the message loop). Shadowing it with a str crashes the screen's
        # message pump on startup and hangs the whole app.
        self._prefill = prefill
        self._context_text = context
        # Used to scan connectors for the proactive untrusted-binary summary
        # shown when the editor is browsed directly (no routing context).
        self._data_dir = data_dir
        # Last message pushed to the status line (mirrored for tests/debug).
        self._status_message = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="trusted-editor-dialog"):
            yield Static("Trusted Binary Locations", id="trusted-editor-title")
            yield DataTable(id="trusted-editor-table", cursor_type="row", zebra_stripes=True)
            yield Input(
                placeholder="Directory to trust (e.g. ~/.local/bin) — Enter to add",
                id="trusted-editor-add",
            )
            yield Static(self._status_text(), id="trusted-editor-status")
            with Horizontal(id="trusted-editor-buttons"):
                yield Button("Add", id="trusted-add", variant="primary")
                yield Button("Remove", id="trusted-remove", variant="error")
                yield Button("Close", id="trusted-close", variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#trusted-editor-table", DataTable)
        table.add_columns("Source", "Status", "Owned", "Path")
        for row in self.rows:
            table.add_row(row.source, row.status, "yes" if row.removable else "—", row.resolved)
        if self.rows:
            table.move_cursor(row=0, column=0, animate=False)
        add_input = self.query_one("#trusted-editor-add", Input)
        if self._prefill:
            add_input.value = self._prefill
        if self._context_text:
            # Routed here for one specific connector — that message wins.
            self._set_status(self._context_text)
        else:
            # Browsed directly: proactively highlight any connector whose
            # binary currently resolves into an untrusted directory.
            summary = self._untrusted_summary()
            if summary:
                self._set_status(summary)
        # Focus the input so the operator can immediately add (or edit) a path.
        add_input.focus()

    def _untrusted_summary(self) -> str:
        """One-line summary of connectors whose binary is in an untrusted dir."""
        try:
            pairs = untrusted_connector_dirs(self._data_dir)
        except Exception:
            return ""
        if not pairs:
            return ""
        names = ", ".join(f"{name} ({directory})" for name, directory in pairs[:3])
        if len(pairs) > 3:
            names += f", +{len(pairs) - 3} more"
        noun = "connector" if len(pairs) == 1 else "connectors"
        return f"⚠ {len(pairs)} {noun} in untrusted dirs: {names} — add the dir to trust it."

    # ----- actions -------------------------------------------------------

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_add(self) -> None:
        path = self.query_one("#trusted-editor-add", Input).value.strip()
        if not path:
            self._set_status("Enter a directory to trust, then press Add.")
            return
        args = ("setup", "trusted-paths", "add", path)
        self.dismiss(
            SetupResourceResult("add", args=args, display_name=" ".join(args), category="setup")
        )

    def action_remove(self) -> None:
        row = self._selected_row()
        if row is None:
            self._set_status("Select a row to remove.")
            return
        if not row.removable:
            self._set_status(
                f"{row.source!r} entries can't be removed here — only operator-added "
                "(.env) prefixes are removable; built-in defaults are protected."
            )
            return
        args = ("setup", "trusted-paths", "remove", row.resolved)
        self.dismiss(
            SetupResourceResult("remove", args=args, display_name=" ".join(args), category="setup")
        )

    # ----- events --------------------------------------------------------

    @on(Input.Submitted, "#trusted-editor-add")
    def _on_add_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_add()

    @on(DataTable.RowHighlighted, "#trusted-editor-table")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.cursor = event.cursor_row

    @on(DataTable.RowSelected, "#trusted-editor-table")
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        self.cursor = event.cursor_row

    @on(Button.Pressed)
    def _on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        match event.button.id:
            case "trusted-add":
                self.action_add()
            case "trusted-remove":
                self.action_remove()
            case "trusted-close":
                self.action_cancel()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    # ----- helpers -------------------------------------------------------

    def _selected_row(self) -> TrustedPathRow | None:
        if not self.rows:
            return None
        return self.rows[max(0, min(self.cursor, len(self.rows) - 1))]

    def _set_status(self, message: str) -> None:
        # Mirror the message onto an attribute so it can be asserted without
        # reaching into Textual's widget-internal render state (which varies
        # across versions). Also handy for debugging.
        self._status_message = message
        self.query_one("#trusted-editor-status", Static).update(message)

    def _status_text(self) -> str:
        return (
            "type a dir + Enter to add · Add/Remove buttons · Del removes selected · Esc close — "
            "only directories you control should be trusted"
        )


def _resolve_data_dir(config: object | Mapping[str, Any] | None) -> str:
    import os  # noqa: PLC0415

    for attr in ("data_dir", "config_dir", "home"):
        val = getattr(config, attr, "")
        if isinstance(val, str) and val:
            return val
    if isinstance(config, Mapping):
        val = config.get("data_dir", "")
        if isinstance(val, str) and val:
            return val
    return os.environ.get("DEFENSECLAW_HOME") or os.path.expanduser("~/.defenseclaw")


def trusted_paths_rows_from_config(config: object | Mapping[str, Any] | None) -> tuple[TrustedPathRow, ...]:
    """Build editor rows from the live trusted-prefix view (defaults + .env + env).

    Reuses ``cmd_setup._collect_trusted_prefixes`` so the editor shows exactly
    what ``defenseclaw setup trusted-paths list`` shows.
    """
    from defenseclaw.commands.cmd_setup import _collect_trusted_prefixes  # noqa: PLC0415

    data_dir = _resolve_data_dir(config)
    try:
        raw = _collect_trusted_prefixes(data_dir)
    except Exception:
        raw = []
    return tuple(
        TrustedPathRow(
            resolved=str(item.get("resolved", "")),
            source=str(item.get("source", "")),
            status=str(item.get("status", "")),
            removable=bool(item.get("removable", False)),
        )
        for item in raw
    )


def _refresh_trusted_prefix_env(data_dir: str | None) -> None:
    """Merge persisted-``.env`` trusted prefixes into the live environment.

    The TUI reads ``DEFENSECLAW_TRUSTED_BIN_PREFIXES`` into ``os.environ`` once
    at launch (``config.load()``). A prefix trusted *after* launch — via the CLI
    or the editor's own Add button, which runs ``trusted-paths add`` in a
    subprocess — never reaches the running process's environment, so a
    same-session discovery scan would still treat it as untrusted. Re-read the
    persisted value and union it into the live one (never dropping anything
    already exported) so the scan reflects current trust without a TUI restart.
    """
    import os  # noqa: PLC0415

    from defenseclaw.commands.cmd_setup import _load_dotenv  # noqa: PLC0415
    from defenseclaw.config import default_data_path  # noqa: PLC0415

    resolved_dir = data_dir or str(default_data_path())
    try:
        persisted = _load_dotenv(os.path.join(resolved_dir, ".env")).get(
            "DEFENSECLAW_TRUSTED_BIN_PREFIXES", ""
        )
    except Exception:
        return
    if not persisted:
        return
    current = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    merged: list[str] = []
    for piece in (*current.split(os.pathsep), *persisted.split(os.pathsep)):
        piece = piece.strip()
        if piece and piece not in merged:
            merged.append(piece)
    os.environ["DEFENSECLAW_TRUSTED_BIN_PREFIXES"] = os.pathsep.join(merged)


_UNTRUSTED_DIR_CACHE: dict[str, str | None] = {}


def _trust_state_token(data_dir: str | None) -> str:
    """Fingerprint persisted + live trust state for short-lived routing cache."""
    import os  # noqa: PLC0415

    from defenseclaw.config import default_data_path  # noqa: PLC0415

    resolved_dir = data_dir or str(default_data_path())
    dotenv = os.path.join(resolved_dir, ".env")
    try:
        mtime = str(os.path.getmtime(dotenv))
    except OSError:
        mtime = "0"
    return f"{mtime}:{os.environ.get('DEFENSECLAW_TRUSTED_BIN_PREFIXES', '')}"


def untrusted_connector_dir(connector: str, data_dir: str | None = None) -> str | None:
    """Return the directory a connector binary lives in when it is *untrusted*.

    Returns ``None`` when the connector is absent, its binary is trusted, or
    discovery fails. Used by the TUI to route an untrusted-binary setup into
    the Trusted Paths editor instead of running a setup that the trust gate
    would refuse (where the CLI would otherwise fire ``click.confirm``).

    Re-hydrates persisted trust and scans connectors. Results are cached per
    connector for the current trust fingerprint so repeated mode-picker opens
    in one session do not re-exec every binary.
    """
    import os  # noqa: PLC0415

    from defenseclaw.inventory import agent_discovery  # noqa: PLC0415

    cache_key = f"{connector}|{_trust_state_token(data_dir)}"
    if cache_key in _UNTRUSTED_DIR_CACHE:
        return _UNTRUSTED_DIR_CACHE[cache_key]

    _refresh_trusted_prefix_env(data_dir)
    try:
        disc = agent_discovery.discover_agents(use_cache=False, refresh=True, data_dir=data_dir)
    except Exception:
        _UNTRUSTED_DIR_CACHE[cache_key] = None
        return None
    signal = disc.agents.get(connector)
    if signal is None or not signal.binary_path:
        result = None
    elif signal.error != agent_discovery.UNTRUSTED_PREFIX_ERROR:
        result = None
    else:
        result = os.path.dirname(os.path.realpath(signal.binary_path))
    _UNTRUSTED_DIR_CACHE[cache_key] = result
    return result


def untrusted_connector_dirs(data_dir: str | None = None) -> list[tuple[str, str]]:
    """All connectors whose binary currently resolves into an untrusted dir.

    Returns ``(connector, parent_dir)`` pairs (deduped, sorted by connector)
    for the *proactive* panel highlight — so an operator browsing the Trusted
    Paths panel can see which connectors are untrusted without first triggering
    setup on each one. One discovery pass scans every connector at once. Returns
    an empty list when discovery fails. Mirrors the ``agent discover`` hint in
    ``cmd_agent`` so the TUI and CLI surface the same set.

    Runs a *fresh* scan (and re-hydrates persisted trust) so the highlight drops
    a directory the moment it is trusted, rather than lagging behind the cache.
    """
    import os  # noqa: PLC0415

    from defenseclaw.inventory import agent_discovery  # noqa: PLC0415

    _refresh_trusted_prefix_env(data_dir)
    try:
        disc = agent_discovery.discover_agents(use_cache=False, refresh=True, data_dir=data_dir)
    except Exception:
        return []
    out: dict[str, str] = {}
    for name, signal in disc.agents.items():
        if signal is None or not signal.binary_path:
            continue
        if signal.error != agent_discovery.UNTRUSTED_PREFIX_ERROR:
            continue
        out.setdefault(name, os.path.dirname(os.path.realpath(signal.binary_path)))
    return sorted(out.items())
