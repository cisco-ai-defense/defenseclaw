# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch fcy-b2: wizard secrets off argv and Activity, idle CPU, run labels."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

import click
import pytest
from defenseclaw.db import Store
from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.panels.setup import (
    OBSERVABILITY_PRESETS,
    WIZARD_SECRET_ENV,
    SetupPanelModel,
    SetupWizard,
    build_wizard_args,
    observability_wizard_fields,
    wizard_form_defs,
    wizard_secrets_to_env,
)
from defenseclaw.tui.services.v8_event_history import V8EventHistoryReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(Path(__file__).resolve().parents[3]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from fixtures import screen_text, snapshot_app  # noqa: E402

from scripts.benchmark_tui_refresh import (  # noqa: E402
    SQLTrace,
    append_synthetic_v8_event,
    create_synthetic_v8_database,
)

MARK = "dccert-wizard-marker-7f3c"


def _filled(fields: Any) -> list[Any]:
    return [field.with_value(MARK) if field.kind == "password" and field.flag else field for field in fields]


def _datadog_intent() -> Any:
    model = SetupPanelModel({})
    model.open_wizard_form(SetupWizard.OBSERVABILITY)
    fields = []
    for field in observability_wizard_fields("datadog"):
        if field.label == "Name":
            field = field.with_value("rs3x-argv-check")
        elif field.label == "Dry Run":
            field = field.with_value("yes")
        fields.append(field)
    model.form_fields = _filled(fields)
    action = model.submit_wizard_form()
    assert action.intent is not None
    return action.intent


def test_no_wizard_puts_a_secret_field_on_argv() -> None:
    # GAP-1888: the child's argv is readable by every local account (ps).
    forms = [(wizard, wizard_form_defs(wizard, {})) for wizard in SetupWizard]
    forms += [(SetupWizard.OBSERVABILITY, observability_wizard_fields(preset)) for preset, _ in OBSERVABILITY_PRESETS]
    checked = 0
    for wizard, fields in forms:
        if not any(field.kind == "password" and field.flag for field in fields):
            continue
        args, env = wizard_secrets_to_env(build_wizard_args(wizard, _filled(fields), {}))
        assert MARK not in " ".join(args), (wizard, args)
        assert env and all(value == MARK for _name, value in env), (wizard, env)
        checked += 1
    assert checked >= 5


def _command(path: tuple[str, ...]) -> click.Command:
    from defenseclaw.main import cli

    command: click.Command = cli
    for word in path:
        assert isinstance(command, click.Group)
        command = command.commands[word]
    if path[-1] == "dashboards":
        command = command.commands["apply"]  # type: ignore[attr-defined]
    return command


@pytest.mark.parametrize(
    ("path", "flag", "env_name"),
    [
        *WIZARD_SECRET_ENV,
        (("init",), "--llm-api-key", "DEFENSECLAW_INIT_LLM_API_KEY"),
        (("init",), "--cisco-api-key", "DEFENSECLAW_INIT_CISCO_API_KEY"),
    ],
)
def test_cli_reads_each_secret_flag_from_its_env_var(path: tuple[str, ...], flag: str, env_name: str) -> None:
    option = next(param for param in _command(path).params if flag in getattr(param, "opts", ()))
    assert option.envvar == env_name
    if env_name.startswith("DEFENSECLAW_"):
        assert "visible to other local users" in (option.help or "")


async def test_datadog_run_keeps_the_key_off_argv_and_out_of_activity(tmp_path) -> None:
    intent = _datadog_intent()
    # GAP-1891: named after the destination, not "Observability / Galileo".
    assert intent.label == "setup Observability / Datadog"
    assert MARK not in " ".join(intent.args)
    assert intent.env_overrides == (("DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN", MARK),)

    app = snapshot_app(tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    async def fake_run(binary: str, args: tuple[str, ...], **kwargs: Any):
        calls.append((tuple(args), kwargs))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=1, duration=0.01)

    async def confirm(_screen: Any) -> bool:
        return True

    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = fake_run  # type: ignore[method-assign]
        app.push_screen_wait = confirm  # type: ignore[method-assign]
        await app._confirm_and_run_intent(intent)
        assert dict(calls[0][1]["env_overrides"]) == {"DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN": MARK}
        assert all(MARK not in arg for arg in calls[0][0])
        assert "Observability / Datadog" in app.status_text

        # GAP-1889: a typed command with the key on argv is shown redacted in
        # Activity, the drawer and Save output; Rerun still has the value.
        typed = ("setup", "observability", "add", "datadog", "--non-interactive", "--token", MARK)
        await app._run_command("defenseclaw", typed)
        await pilot.pause()
        entry = app.activity_model.entries[-1]
        assert "--token <redacted>" in entry.command and MARK not in entry.command
        assert MARK not in app.activity_model.render_text(height=200)
        assert MARK not in screen_text(app)
        assert MARK not in repr(entry)
        app._handle_activity_key("!")
        await app.workers.wait_for_complete()
        assert calls[-1][0] == typed


def _alert_ids(reader: V8EventHistoryReader, alert_limit: int = 500) -> list[str]:
    _history, alerts, _mutations = reader.load_views_and_mutations(1000, alert_limit, 500)
    return [row.id for row in alerts]


@pytest.mark.parametrize("alert_limit", [500, 5])
def test_alert_scan_after_new_rows_reads_only_the_new_rows(tmp_path, alert_limit: int) -> None:
    # GAP-1816: every gateway write re-ran the alert filter over the whole
    # audit table (seconds of CPU on a 1.3 GB audit.db while idle).
    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 40)
    store = Store.open_read_only(str(path), timeout=1)
    trace = SQLTrace()
    store.db.set_trace_callback(trace)
    try:
        reader = V8EventHistoryReader(store)
        _alert_ids(reader, alert_limit)
        assert not any("NOT INDEXED" in statement for statement in trace.statements)
        for index in range(40, 52):
            append_synthetic_v8_event(path, index)
        trace.statements.clear()
        incremental = _alert_ids(reader, alert_limit)
        assert any("NOT INDEXED" in statement and "json_each" in statement for statement in trace.statements)
        assert incremental == _alert_ids(V8EventHistoryReader(store), alert_limit)

        # A pruned alert in a full window: older alerts must fill the gap.
        writer = sqlite3.connect(path)
        writer.execute("DELETE FROM audit_events WHERE id = ?", (incremental[0],))
        writer.commit()
        writer.close()
        assert _alert_ids(reader, alert_limit) == _alert_ids(V8EventHistoryReader(store), alert_limit)
    finally:
        store.close()


def test_audit_blocks_after_new_rows_read_only_the_new_rows(tmp_path) -> None:
    from defenseclaw.tui.services.read_repository import TUIReadRepository

    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 40)
    repository = TUIReadRepository(path)
    store = Store.open_read_only(str(path), timeout=1)
    try:
        repository._block_summaries(store, 500)  # noqa: SLF001
        for index in range(40, 48):
            append_synthetic_v8_event(path, index)
        trace = SQLTrace()
        store.db.set_trace_callback(trace)
        rows = repository._block_summaries(store, 500)  # noqa: SLF001
        store.db.set_trace_callback(None)
        assert [event.id for event in rows] == [event.id for event in store.list_block_event_summaries(500)]
        assert any("NOT INDEXED" in statement and "rowid >" in statement for statement in trace.statements)
    finally:
        store.close()
        repository.close()
