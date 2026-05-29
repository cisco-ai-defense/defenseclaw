# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TUI persistent state store."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from defenseclaw.tui.services.tui_state import (
    PALETTE_MRU_LIMIT,
    STATE_FILENAME,
    TUIState,
    TUIStateStore,
)


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "data"


def test_load_returns_defaults_when_missing(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    state = store.load()

    assert state == TUIState()
    assert store.path == state_dir / STATE_FILENAME
    assert not store.path.exists()


def test_save_writes_atomically_with_mode_0600(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    state = store.load()
    store.record_command("scan-all")
    assert store.save() is True

    path = store.path
    assert path.exists()
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["palette_mru"] == ["scan-all"]
    assert body["active_panel"] == "overview"

    mode = path.stat().st_mode & 0o777
    assert mode == 0o600

    parent_mode = path.parent.stat().st_mode & 0o777
    assert parent_mode == 0o700


def test_round_trip_preserves_all_fields(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    store.set_active_panel("alerts")
    store.record_command("doctor")
    store.record_command("scan-all")
    store.mark_seen("alerts", datetime(2026, 5, 20, 12, tzinfo=timezone.utc))
    store.set_panel_filter("logs", "level=error")
    store.save()

    other = TUIStateStore(state_dir)
    reloaded = other.load()
    assert reloaded.active_panel == "alerts"
    assert reloaded.palette_mru == ("scan-all", "doctor")
    assert reloaded.panel_last_seen == {"alerts": "2026-05-20T12:00:00+00:00"}
    assert reloaded.panel_filters == {"logs": "level=error"}


def test_mru_evicts_after_limit(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    for i in range(PALETTE_MRU_LIMIT + 3):
        store.record_command(f"cmd-{i}")
    state = store.state

    assert len(state.palette_mru) == PALETTE_MRU_LIMIT
    assert state.palette_mru[0] == f"cmd-{PALETTE_MRU_LIMIT + 2}"


def test_mru_bumps_existing_to_front(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    store.record_command("a")
    store.record_command("b")
    store.record_command("c")
    store.record_command("a")

    assert store.state.palette_mru == ("a", "c", "b")


def test_record_command_ignores_empty(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    store.record_command("")
    store.record_command("   ")
    assert store.state.palette_mru == ()


def test_corrupt_payload_is_quarantined(state_dir: Path) -> None:
    state_dir.mkdir(parents=True)
    state_path = state_dir / STATE_FILENAME
    state_path.write_text("{not valid json", encoding="utf-8")

    store = TUIStateStore(state_dir)
    state = store.load()

    assert state == TUIState()
    backup = state_path.with_suffix(state_path.suffix + ".bak")
    assert backup.exists()
    assert not state_path.exists()


def test_mark_seen_writes_iso_timestamp(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    store.mark_seen("logs", now)

    assert store.get_last_seen("logs") == now


def test_set_panel_filter_clears_on_empty(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    store.set_panel_filter("alerts", "severity=high")
    assert store.get_panel_filter("alerts") == "severity=high"

    store.set_panel_filter("alerts", "")
    assert store.get_panel_filter("alerts") == ""
    assert "alerts" not in store.state.panel_filters


def test_set_active_panel_no_change_skips_update(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    store.load()
    before = store.state
    after = store.set_active_panel("overview")
    assert after is before


def test_theme_defaults_to_empty(state_dir: Path) -> None:
    """Fresh state has no theme override so the app uses its default."""

    store = TUIStateStore(state_dir)
    state = store.load()
    assert state.theme == ""
    assert store.get_theme() == ""


def test_set_theme_persists_and_round_trips(state_dir: Path) -> None:
    """``set_theme`` is mirrored into the saved JSON and reloads cleanly."""

    store = TUIStateStore(state_dir)
    store.load()
    store.set_theme("tokyo-night")
    assert store.save() is True
    assert store.get_theme() == "tokyo-night"

    other = TUIStateStore(state_dir)
    reloaded = other.load()
    assert reloaded.theme == "tokyo-night"


def test_set_theme_strips_whitespace_and_clears(state_dir: Path) -> None:
    """Whitespace-only input is treated as 'clear my theme override'."""

    store = TUIStateStore(state_dir)
    store.load()
    store.set_theme("  nord  ")
    assert store.get_theme() == "nord"
    store.set_theme("   ")
    assert store.get_theme() == ""


def test_set_theme_no_change_returns_same_state(state_dir: Path) -> None:
    """Re-setting the same theme is a no-op to avoid spurious save churn."""

    store = TUIStateStore(state_dir)
    store.load()
    store.set_theme("dracula")
    before = store.state
    after = store.set_theme("dracula")
    assert after is before


def test_legacy_state_file_without_theme_loads(state_dir: Path) -> None:
    """State files written before the theme field MUST migrate cleanly."""

    state_dir.mkdir(parents=True)
    state_path = state_dir / STATE_FILENAME
    state_path.write_text(
        json.dumps(
            {
                "active_panel": "logs",
                "palette_mru": ["doctor"],
                # No ``theme`` key — older builds didn't write one.
            }
        ),
        encoding="utf-8",
    )
    store = TUIStateStore(state_dir)
    state = store.load()
    assert state.active_panel == "logs"
    assert state.theme == ""


def test_save_to_readonly_path_returns_false(state_dir: Path) -> None:
    state_dir.mkdir(parents=True)
    state_dir.chmod(0o500)
    try:
        store = TUIStateStore(state_dir)
        store.load()
        store.record_command("doctor")
        assert store.save() is False
    finally:
        state_dir.chmod(0o700)


def test_load_handles_unreadable_file(state_dir: Path) -> None:
    state_dir.mkdir(parents=True)
    state_path = state_dir / STATE_FILENAME
    state_path.write_text("{}", encoding="utf-8")
    state_path.chmod(0o000)
    try:
        store = TUIStateStore(state_dir)
        state = store.load()
        # Either the load succeeds (root) or returns defaults (most CI).
        # Either way the TUI must not crash.
        assert isinstance(state, TUIState)
    finally:
        state_path.chmod(0o600)


def test_no_data_dir_makes_store_ephemeral(tmp_path: Path) -> None:
    """Without a data_dir the store must not touch the operator's home."""

    store = TUIStateStore(None)
    assert store.path is None
    assert store.persistent is False

    state = store.load()
    assert state == TUIState()

    store.record_command("doctor")
    store.set_active_panel("alerts")
    assert store.save() is False
    assert store.state.palette_mru == ("doctor",)
    assert store.state.active_panel == "alerts"


def test_data_dir_overrides_home(state_dir: Path) -> None:
    store = TUIStateStore(state_dir)
    assert store.path == state_dir / STATE_FILENAME


def test_palette_mru_invalid_entries_are_skipped(state_dir: Path) -> None:
    state_dir.mkdir(parents=True)
    state_path = state_dir / STATE_FILENAME
    state_path.write_text(
        json.dumps(
            {
                "active_panel": "logs",
                "palette_mru": ["doctor", "", 42, None, "  ", "scan-all"],
            }
        ),
        encoding="utf-8",
    )

    store = TUIStateStore(state_dir)
    state = store.load()
    assert state.palette_mru == ("doctor", "scan-all")
    assert state.active_panel == "logs"
