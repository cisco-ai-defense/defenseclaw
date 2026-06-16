# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup resource editor (audit sinks / webhooks) modal tests."""

from __future__ import annotations

import pytest
from defenseclaw.tui.screens.setup_resource_editor import (
    SetupResourceEditorScreen,
    SetupResourceResult,
    SetupResourceRow,
)
from textual.app import App, ComposeResult
from textual.widgets import Static

_SINK = SetupResourceRow(name="splunk", kind="splunk_hec", endpoint="https://x", enabled=True)
_HOOK = SetupResourceRow(name="hook1", kind="webhook", endpoint="https://y", enabled=True)


class _Harness(App[SetupResourceResult | None]):
    def __init__(self, kind: str, rows: tuple[SetupResourceRow, ...]) -> None:
        super().__init__()
        self._kind = kind
        self._rows = rows
        self.result: object = "__UNSET__"

    def compose(self) -> ComposeResult:
        yield Static("resource editor harness")

    def on_mount(self) -> None:
        self.push_screen(SetupResourceEditorScreen(self._kind, self._rows), self._set)

    def _set(self, result: SetupResourceResult | None) -> None:
        self.result = result


@pytest.mark.asyncio
async def test_audit_sink_enter_key_does_not_dispatch_network_test() -> None:
    # Reflexive Enter on an audit-sink row must NOT fire a live outbound test.
    app = _Harness("audit_sinks", (_SINK,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert app.result == "__UNSET__"  # nothing dismissed -> no network argv


@pytest.mark.asyncio
async def test_audit_sink_default_action_only_selects() -> None:
    app = _Harness("audit_sinks", (_SINK,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.cursor = 0
        app.screen.action_default()
        await pilot.pause()
        assert app.result == "__UNSET__"
        status = str(app.screen.query_one("#resource-editor-status", Static).content)
        assert "Test" in status


@pytest.mark.asyncio
async def test_audit_sink_explicit_test_dispatches_network_argv() -> None:
    # The Test action still works when explicitly invoked (t / Test button).
    app = _Harness("audit_sinks", (_SINK,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.cursor = 0
        app.screen.action_test()
        await pilot.pause()
        assert isinstance(app.result, SetupResourceResult)
        assert app.result.args == ("setup", "observability", "test", "splunk")


@pytest.mark.asyncio
async def test_webhook_default_action_is_read_only_show() -> None:
    app = _Harness("webhooks", (_HOOK,))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.screen.cursor = 0
        app.screen.action_default()
        await pilot.pause()
        assert isinstance(app.result, SetupResourceResult)
        assert app.result.args == ("setup", "webhook", "show", "hook1")
