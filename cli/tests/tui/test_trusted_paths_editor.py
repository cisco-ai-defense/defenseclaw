# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the native Trusted Paths setup editor modal."""

from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.inventory import agent_discovery as ad
from defenseclaw.tui.screens.setup_resource_editor import SetupResourceResult
from defenseclaw.tui.screens import trusted_paths_editor as tpe
from defenseclaw.tui.screens.trusted_paths_editor import (
    TrustedPathRow,
    TrustedPathsEditorScreen,
    _refresh_trusted_prefix_env,
    trusted_paths_rows_from_config,
    untrusted_connector_dir,
    untrusted_connector_dirs,
)
from textual.app import App, ComposeResult
from textual.widgets import Input, Static

_DEFAULT_ROW = TrustedPathRow("/usr/bin", "default", "ok", False)
_OPERATOR_ROW = TrustedPathRow("/opt/acme/bin", ".env", "missing", True)


@pytest.fixture(autouse=True)
def _isolate_trusted_env(tmp_path, monkeypatch):
    """Point DEFENSECLAW_HOME at an empty dir so the new ``_refresh`` helper
    reads no persisted ``.env`` and never mutates the real process env across
    tests. Individual tests that need a populated ``.env`` write into tmp_path."""
    tpe._UNTRUSTED_DIR_CACHE.clear()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)
    yield tmp_path
    tpe._UNTRUSTED_DIR_CACHE.clear()


class _Harness(App):
    def __init__(self, rows: tuple[TrustedPathRow, ...], *, prefill: str = "", context: str = "") -> None:
        super().__init__()
        self._rows = rows
        self._prefill = prefill
        # NOTE: not ``_context`` — that name is reserved by Textual's
        # MessagePump (called as ``with self._context():`` in the message
        # loop); shadowing it with a str crashes the app's pump and hangs.
        self._context_text = context
        self.result: SetupResourceResult | None = None

    def compose(self) -> ComposeResult:
        yield Static("trusted-paths harness")

    def on_mount(self) -> None:
        self.push_screen(
            TrustedPathsEditorScreen(self._rows, prefill=self._prefill, context=self._context_text),
            self._set_result,
        )

    def _set_result(self, result: SetupResourceResult | None) -> None:
        self.result = result


def _disc(signal: ad.AgentSignal) -> ad.AgentDiscovery:
    return ad.AgentDiscovery(scanned_at="t", agents={"codex": signal}, cache_hit=False)


def _sig(binary_path: str, error: str, version: str = "") -> ad.AgentSignal:
    return ad.AgentSignal(
        name="codex",
        installed=True,
        config_path="",
        binary_path=binary_path,
        version=version,
        error=error,
    )


def test_untrusted_connector_dir_detects_untrusted_binary() -> None:
    disc = _disc(_sig("/home/u/.local/bin/codex", ad.UNTRUSTED_PREFIX_ERROR))
    with patch.object(ad, "discover_agents", return_value=disc) as mock_disc:
        result = untrusted_connector_dir("codex")
        untrusted_connector_dir("codex")
    assert mock_disc.call_count == 1
    assert result == os.path.dirname(os.path.realpath("/home/u/.local/bin/codex"))


def test_untrusted_connector_dir_none_when_trusted() -> None:
    disc = _disc(_sig("/usr/bin/codex", "", version="1.0"))
    with patch.object(ad, "discover_agents", return_value=disc):
        assert untrusted_connector_dir("codex") is None


def test_untrusted_connector_dir_none_when_connector_absent() -> None:
    disc = ad.AgentDiscovery(scanned_at="t", agents={}, cache_hit=False)
    with patch.object(ad, "discover_agents", return_value=disc):
        assert untrusted_connector_dir("codex") is None


def test_rows_from_config_reflect_collect_view() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
            fh.write("DEFENSECLAW_TRUSTED_BIN_PREFIXES=/opt/acme/bin\n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_TRUSTED_BIN_PREFIXES", None)
            rows = trusted_paths_rows_from_config(SimpleNamespace(data_dir=tmp))
    resolved = {r.resolved: r for r in rows}
    assert "/usr/bin" in resolved  # a built-in default
    assert not resolved["/usr/bin"].removable
    assert "/opt/acme/bin" in resolved  # operator-added via .env
    assert resolved["/opt/acme/bin"].source == ".env"
    assert resolved["/opt/acme/bin"].removable


@pytest.mark.asyncio
async def test_add_via_input_returns_cli_args() -> None:
    app = _Harness((_DEFAULT_ROW,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.query_one("#trusted-editor-add", Input).value = "/opt/tools"
        app.screen.action_add()
        await pilot.pause()
    assert isinstance(app.result, SetupResourceResult)
    assert app.result.action == "add"
    assert app.result.args == ("setup", "trusted-paths", "add", "/opt/tools")


@pytest.mark.asyncio
async def test_remove_removable_row_returns_cli_args() -> None:
    app = _Harness((_OPERATOR_ROW,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.cursor = 0
        app.screen.action_remove()
        await pilot.pause()
    assert isinstance(app.result, SetupResourceResult)
    assert app.result.action == "remove"
    assert app.result.args == ("setup", "trusted-paths", "remove", "/opt/acme/bin")


@pytest.mark.asyncio
async def test_remove_default_row_is_refused() -> None:
    app = _Harness((_DEFAULT_ROW,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.cursor = 0
        app.screen.action_remove()
        await pilot.pause()
        # No dismissal happened: a built-in default cannot be removed, so the
        # editor is still the active modal.
        assert isinstance(app.screen, TrustedPathsEditorScreen)
    assert app.result is None


@pytest.mark.asyncio
async def test_empty_add_is_refused() -> None:
    app = _Harness((_DEFAULT_ROW,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.action_add()  # input is empty
        await pilot.pause()
    assert app.result is None


@pytest.mark.asyncio
async def test_escape_dismisses_without_action() -> None:
    app = _Harness((_OPERATOR_ROW,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None


@pytest.mark.asyncio
async def test_prefill_seeds_the_add_field() -> None:
    app = _Harness((_OPERATOR_ROW,), prefill="/opt/acme/bin", context="trust this dir")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        value = app.screen.query_one("#trusted-editor-add", Input).value
    assert value == "/opt/acme/bin"


@pytest.mark.asyncio
async def test_prefill_path_can_be_added_directly() -> None:
    app = _Harness((_OPERATOR_ROW,), prefill="/opt/acme/bin")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.action_add()  # uses the pre-filled value, no typing needed
        await pilot.pause()
    assert isinstance(app.result, SetupResourceResult)
    assert app.result.args == ("setup", "trusted-paths", "add", "/opt/acme/bin")


# ---- proactive untrusted-connector highlight ------------------------------


def _multi_disc(agents: dict[str, ad.AgentSignal]) -> ad.AgentDiscovery:
    return ad.AgentDiscovery(scanned_at="t", agents=agents, cache_hit=False)


def _agent(name: str, binary_path: str, error: str, version: str = "") -> ad.AgentSignal:
    return ad.AgentSignal(
        name=name,
        installed=True,
        config_path="",
        binary_path=binary_path,
        version=version,
        error=error,
    )


def test_untrusted_connector_dirs_lists_every_untrusted_connector() -> None:
    disc = _multi_disc(
        {
            "codex": _agent("codex", "/home/u/.local/bin/codex", ad.UNTRUSTED_PREFIX_ERROR),
            "claudecode": _agent("claudecode", "/opt/foo/claude", ad.UNTRUSTED_PREFIX_ERROR),
            "cursor": _agent("cursor", "/usr/bin/cursor", "", version="1.0"),  # trusted
        }
    )
    with patch.object(ad, "discover_agents", return_value=disc):
        pairs = untrusted_connector_dirs()
    names = [name for name, _ in pairs]
    assert names == ["claudecode", "codex"]  # sorted, trusted cursor excluded
    assert dict(pairs)["codex"] == os.path.dirname(os.path.realpath("/home/u/.local/bin/codex"))


def test_untrusted_connector_dirs_empty_when_all_trusted() -> None:
    disc = _multi_disc({"cursor": _agent("cursor", "/usr/bin/cursor", "", version="1.0")})
    with patch.object(ad, "discover_agents", return_value=disc):
        assert untrusted_connector_dirs() == []


def test_untrusted_summary_names_every_connector_no_cap() -> None:
    # >3 untrusted connectors: the summary must name them all (the old code
    # capped at 3 and collapsed the rest into "+N more").
    agents = {
        f"c{i}": _agent(f"c{i}", f"/home/u/.local/bin/c{i}", ad.UNTRUSTED_PREFIX_ERROR)
        for i in range(5)
    }
    with patch.object(ad, "discover_agents", return_value=_multi_disc(agents)):
        summary = TrustedPathsEditorScreen((_DEFAULT_ROW,))._untrusted_summary()
    assert "more" not in summary
    for i in range(5):
        assert f"c{i}" in summary


# ---- fix (a): a load failure must not look like an empty allow-list --------


def test_rows_from_config_surfaces_load_error_as_sentinel() -> None:
    from defenseclaw.commands import cmd_setup

    with patch.object(cmd_setup, "_collect_trusted_prefixes", side_effect=OSError("disk boom")):
        rows = trusted_paths_rows_from_config(SimpleNamespace(data_dir="/x"))

    assert len(rows) == 1
    assert rows[0].error is True
    assert "disk boom" in rows[0].resolved


@pytest.mark.asyncio
async def test_editor_surfaces_load_error_instead_of_empty_list() -> None:
    from textual.widgets import DataTable

    err_row = TrustedPathRow("disk read failed", "<error>", "load failed", False, error=True)
    app = _Harness((err_row,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        screen = app.screen
        # The sentinel is NOT a selectable/removable data row.
        assert screen.rows == ()
        assert screen._selected_row() is None
        # The failure is surfaced loudly (not a clean empty allow-list).
        assert "Could not read" in screen._status_message
        assert "UNKNOWN" in screen._status_message
        # And a visible error row is shown in the table.
        assert screen.query_one("#trusted-editor-table", DataTable).row_count == 1


@pytest.mark.asyncio
async def test_editor_shows_untrusted_summary_when_browsed() -> None:
    """Opened directly (no routing context) the editor surfaces a one-line
    summary of connectors whose binary resolves into an untrusted dir."""
    disc = _multi_disc(
        {"codex": _agent("codex", "/home/u/.local/bin/codex", ad.UNTRUSTED_PREFIX_ERROR)}
    )
    app = _Harness((_DEFAULT_ROW,))  # no prefill, no context
    with patch.object(ad, "discover_agents", return_value=disc):
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = app.screen._status_message
    assert "codex" in text
    assert "untrusted" in text.lower()


@pytest.mark.asyncio
async def test_editor_routing_context_wins_over_summary() -> None:
    """When routed for a specific connector, that context message is shown
    instead of the generic untrusted-connectors summary."""
    disc = _multi_disc(
        {"codex": _agent("codex", "/home/u/.local/bin/codex", ad.UNTRUSTED_PREFIX_ERROR)}
    )
    app = _Harness((_DEFAULT_ROW,), context="Claude Code binary is outside a trusted prefix.")
    with patch.object(ad, "discover_agents", return_value=disc):
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = app.screen._status_message
    assert text == "Claude Code binary is outside a trusted prefix."


# ---- fix (a): fresh scan reflects current trust without a restart ----------


def test_refresh_merges_persisted_env(tmp_path, monkeypatch):
    """A prefix persisted to .env after launch is unioned into the live env,
    without dropping anything already exported."""
    (tmp_path / ".env").write_text(
        "DEFENSECLAW_TRUSTED_BIN_PREFIXES=/opt/foo\n", encoding="utf-8"
    )
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "/opt/bar")
    _refresh_trusted_prefix_env(str(tmp_path))
    parts = os.environ["DEFENSECLAW_TRUSTED_BIN_PREFIXES"].split(os.pathsep)
    assert "/opt/bar" in parts  # exported value preserved
    assert "/opt/foo" in parts  # persisted value merged in


def test_refresh_noop_without_persisted_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "/opt/bar")
    _refresh_trusted_prefix_env(str(tmp_path))  # tmp_path has no .env
    assert os.environ["DEFENSECLAW_TRUSTED_BIN_PREFIXES"] == "/opt/bar"


def test_untrusted_dirs_forces_fresh_discovery() -> None:
    """The highlight must re-scan (no stale cache) so it drops a dir the moment
    it is trusted."""
    captured = {}

    def _fake(**kwargs):
        captured.update(kwargs)
        return _multi_disc({})

    with patch.object(ad, "discover_agents", side_effect=_fake):
        untrusted_connector_dirs()
    assert captured.get("use_cache") is False
    assert captured.get("refresh") is True


def test_untrusted_dir_reflects_newly_trusted_prefix(tmp_path, monkeypatch) -> None:
    """End-to-end for fix (a): once a dir is persisted to .env, a connector
    whose binary lives there is no longer reported untrusted."""
    bindir = tmp_path / "tools"
    bindir.mkdir()
    binpath = str(bindir / "codex")

    def _disc_respecting_env(**kwargs):
        prefixes = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
        trusted = str(bindir) in prefixes.split(os.pathsep)
        err = "" if trusted else ad.UNTRUSTED_PREFIX_ERROR
        return _multi_disc({"codex": _agent("codex", binpath, err, version="1.0" if trusted else "")})

    with patch.object(ad, "discover_agents", side_effect=_disc_respecting_env):
        # Before trusting: codex is flagged.
        assert untrusted_connector_dir("codex", str(tmp_path)) == str(bindir)
        # Persist the trust to .env, then re-scan: codex drops off.
        (tmp_path / ".env").write_text(
            f"DEFENSECLAW_TRUSTED_BIN_PREFIXES={bindir}\n", encoding="utf-8"
        )
        assert untrusted_connector_dir("codex", str(tmp_path)) is None
