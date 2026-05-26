# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TUI toast manager."""

from __future__ import annotations

from defenseclaw.tui.widgets.toasts import (
    MAX_TOASTS,
    TTL_ERROR,
    TTL_INFO,
    TTL_SUCCESS,
    TTL_WARN,
    Toast,
    ToastManager,
)


def test_push_returns_toast_with_correct_ttl() -> None:
    mgr = ToastManager()
    info = mgr.push("info", "hello", now=100.0)
    assert info.expires_at == 100.0 + TTL_INFO
    success = mgr.push("success", "ok", now=100.0)
    assert success.expires_at == 100.0 + TTL_SUCCESS
    warn = mgr.push("warn", "watch out", now=100.0)
    assert warn.expires_at == 100.0 + TTL_WARN
    # Cap at MAX_TOASTS=3, so the fourth push evicts the oldest.
    error = mgr.push("error", "boom", now=100.0)
    assert error.expires_at == 100.0 + TTL_ERROR


def test_max_toasts_evicts_oldest() -> None:
    mgr = ToastManager()
    for i in range(MAX_TOASTS + 2):
        mgr.push("info", f"msg-{i}", now=0.0)
    assert len(mgr.items) == MAX_TOASTS
    assert [t.message for t in mgr.items] == [
        f"msg-{i}" for i in range(2, MAX_TOASTS + 2)
    ]


def test_tick_prunes_expired_only() -> None:
    mgr = ToastManager()
    mgr.push("info", "old", now=0.0)        # expires at 0 + TTL_INFO = 4
    mgr.push("error", "fresh", now=5.0)     # expires at 5 + TTL_ERROR = 13

    assert mgr.tick(now=4.5) is True
    assert [t.message for t in mgr.items] == ["fresh"]

    assert mgr.tick(now=6.0) is False
    assert [t.message for t in mgr.items] == ["fresh"]


def test_tick_returns_false_when_nothing_changes() -> None:
    mgr = ToastManager()
    assert mgr.tick(now=0.0) is False
    mgr.push("info", "x", now=0.0)
    assert mgr.tick(now=0.5) is False


def test_clear_empties_queue() -> None:
    mgr = ToastManager()
    mgr.push("error", "boom", now=0.0)
    assert mgr.has_items() is True
    mgr.clear()
    assert mgr.has_items() is False


def test_glyph_mapping_is_ascii_only() -> None:
    """Codeguard-0: glyphs must work on monochrome terminals."""

    mgr = ToastManager()
    for level, expected in (
        ("info", "--"),
        ("success", "OK"),
        ("warn", "!!"),
        ("error", "ERR"),
    ):
        toast = mgr.push(level, "msg", now=0.0)  # type: ignore[arg-type]
        assert toast.glyph == expected


def test_unknown_level_falls_back_to_info_ttl() -> None:
    mgr = ToastManager()
    weird = mgr.push("debug", "?", now=0.0)  # type: ignore[arg-type]
    assert weird.expires_at == TTL_INFO


def test_push_after_tick_extends_queue() -> None:
    mgr = ToastManager()
    mgr.push("info", "first", now=0.0)
    mgr.tick(now=5.0)  # expires first
    mgr.push("success", "second", now=5.0)
    assert [t.message for t in mgr.items] == ["second"]


def test_toast_is_immutable() -> None:
    from dataclasses import FrozenInstanceError

    toast = Toast(level="info", message="hi", expires_at=0.0)
    import pytest

    with pytest.raises(FrozenInstanceError):
        toast.message = "mutated"  # type: ignore[misc]
