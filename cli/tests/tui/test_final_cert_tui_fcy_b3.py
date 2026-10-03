# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch fcy-b3: no timed full rescan on idle, typed secret flags."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

from defenseclaw.db import Store
from defenseclaw.tui.command_line import parse_command_line
from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.services import read_repository, v8_event_history
from defenseclaw.tui.services.read_repository import TUIReadRepository
from defenseclaw.tui.services.v8_event_history import V8EventHistoryReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(Path(__file__).resolve().parents[3]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from fixtures import snapshot_app  # noqa: E402

from scripts.benchmark_tui_refresh import (  # noqa: E402
    SQLTrace,
    append_synthetic_v8_event,
    create_synthetic_v8_database,
)

MARK = "dccert-palette-marker-7f3c"


def _write(path: Path, *statements: tuple[str, tuple[Any, ...]]) -> None:
    writer = sqlite3.connect(path)
    for sql, params in statements:
        writer.execute(sql, params)
    writer.commit()
    writer.close()


def _alert_ids(reader: V8EventHistoryReader) -> list[str]:
    return [row.id for row in reader.load_views_and_mutations(1000, 500, 500)[1]]


def test_idle_reads_never_rescan_every_row_on_a_timer(tmp_path, monkeypatch) -> None:
    # GAP-2007: every 5 minutes the alert and block reads walked the whole
    # audit table again (7-10 CPU-s on an idle TUI with a 1.3 GB audit.db).
    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 40)
    _write(path, ("CREATE TABLE alert_acknowledgement_projection (alert_id TEXT PRIMARY KEY)", ()))
    store = Store.open_read_only(str(path), timeout=1)
    repository = TUIReadRepository(path)
    try:
        reader = V8EventHistoryReader(store)
        first = _alert_ids(reader)
        repository._block_summaries(store, 500)  # noqa: SLF001
        monkeypatch.setattr(v8_event_history, "monotonic", lambda: 1e12, raising=False)
        monkeypatch.setattr(read_repository, "monotonic", lambda: 1e12)

        _write(path, ("INSERT INTO alert_acknowledgement_projection VALUES (?)", (first[0],)))
        trace = SQLTrace()
        store.db.set_trace_callback(trace)
        for index in range(40, 46):
            append_synthetic_v8_event(path, index)
            alerts = _alert_ids(reader)
            blocks = repository._block_summaries(store, 500)  # noqa: SLF001
        store.db.set_trace_callback(None)
        assert all("NOT INDEXED" in sql for sql in trace.statements if "newest_alerts" in sql)
        assert all("rowid >" in sql for sql in trace.statements if "LIKE '%block%'" in sql)
        assert first[0] not in alerts
        assert alerts == _alert_ids(V8EventHistoryReader(store))
        assert [event.id for event in blocks] == [event.id for event in store.list_block_event_summaries(500)]

        # A removed ack brings its alert back; a pruned block leaves the list.
        _write(
            path,
            ("DELETE FROM alert_acknowledgement_projection", ()),
            ("DELETE FROM audit_events WHERE id = ?", (blocks[-1].id,)),
        )
        assert _alert_ids(reader) == _alert_ids(V8EventHistoryReader(store))
        assert first[0] in _alert_ids(reader)
        blocks = repository._block_summaries(store, 500)  # noqa: SLF001
        assert [event.id for event in blocks] == [event.id for event in store.list_block_event_summaries(500)]
    finally:
        store.close()
        repository.close()


def test_typed_secret_flag_is_redacted_in_the_command_name() -> None:
    for text in (
        f"setup observability add datadog --non-interactive --token {MARK}",
        f"defenseclaw setup observability add datadog --token={MARK}",
    ):
        parsed = parse_command_line(text)
        assert MARK not in parsed.display_name
        assert "<redacted>" in parsed.display_name


async def test_typed_secret_flag_stays_off_argv_status_and_drawer(tmp_path) -> None:
    # GAP-2010: the status bar ("Done: ... --token <value>") and the drawer's
    # "Cancelled:" line echoed a palette-typed key, and ps showed it on argv.
    app = snapshot_app(tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    written: list[str] = []

    async def fake_run(binary: str, args: tuple[str, ...], **kwargs: Any):
        calls.append((tuple(args), kwargs))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    parsed = parse_command_line(f"setup observability add datadog --non-interactive --dry-run --token {MARK}")
    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = fake_run  # type: ignore[method-assign]
        write_activity = app._write_activity
        app._write_activity = lambda text, *a, **k: (written.append(text), write_activity(text, *a, **k))[1]

        async def answer_no(_screen: Any) -> bool:
            return False

        async def answer_yes(_screen: Any) -> bool:
            return True

        app.push_screen_wait = answer_no  # type: ignore[method-assign]
        await app._confirm_and_run_parsed(parsed)
        app.push_screen_wait = answer_yes  # type: ignore[method-assign]
        await app._confirm_and_run_parsed(parsed)
        await pilot.pause()

        assert any(line.startswith("[#FBBF24]Cancelled:[/]") for line in written)
        assert MARK not in "\n".join(written)
        assert app.status_text.startswith("Done: ") and MARK not in app.status_text
        assert MARK not in " ".join(app.state_store.state.palette_mru)
        args, kwargs = calls[-1]
        assert MARK not in " ".join(args) and "--token" not in args
        assert dict(kwargs["env_overrides"]) == {"DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN": MARK}
