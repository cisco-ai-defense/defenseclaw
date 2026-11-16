# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Claude Desktop and Cowork facts in AI discovery output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from defenseclaw.commands import cmd_agent
from defenseclaw.inventory.claude_desktop import ClaudeDesktopInfo, format_bytes
from defenseclaw.tui.panels.ai_discovery import AIDiscoveryPanelModel, AIUsageSnapshot

# What the gateway sends for the real Cowork Mac (Claude Desktop 4.4212.0).
COWORK_MAC = {
    "installed": True,
    "installed_source": "app_bundle",
    "version": "4.4212.0",
    "cowork_enabled": True,
    "cowork_enabled_source": "cowork_sessions",
    "engine_version": "2.1.309",
    "vm_bundle_present": True,
    "vm_bundle_bytes": 12161047888,
    "cowork_plugins": ["finance", "sales-tools"],
}


def _signal(block: dict | None) -> dict:
    sig = {
        "signal_id": "s1",
        "state": "seen",
        "category": "desktop_app",
        "product": "Claude Desktop",
        "vendor": "Anthropic",
        "detector": "claude_desktop",
        "basenames": ["Claude"],
    }
    if block is not None:
        sig["claude_desktop"] = block
    return sig


def test_summary_of_a_cowork_mac() -> None:
    info = ClaudeDesktopInfo.from_mapping(COWORK_MAC)
    assert info is not None
    assert info.summary() == (
        "app 4.4212.0; engine 2.1.309; cowork on (cowork_sessions); vm bundle 11.3 GiB; plugins finance, sales-tools"
    )


def test_cowork_unknown_is_never_reported_as_on_or_off() -> None:
    # The gateway sends null for unknown; anything that is not a JSON bool is unknown too.
    for raw in (None, "true", 1, "yes"):
        info = ClaudeDesktopInfo.from_mapping({"installed": True, "cowork_enabled": raw})
        assert info is not None and info.cowork_enabled is None
        assert "cowork unknown" in info.summary()
    off = ClaudeDesktopInfo.from_mapping(
        {"cowork_enabled": False, "cowork_enabled_source": "vm_support_probe", "vm_bundle_present": False}
    )
    assert off is not None
    assert off.summary() == "app not found; cowork off (vm_support_probe); no vm bundle"


def test_from_mapping_is_defensive() -> None:
    assert ClaudeDesktopInfo.from_mapping(None) is None
    assert ClaudeDesktopInfo.from_mapping({}) is None
    assert ClaudeDesktopInfo.from_mapping("claude") is None
    odd = ClaudeDesktopInfo.from_mapping(
        {"installed": "yes", "vm_bundle_bytes": "lots", "cowork_plugins": "a", "vm_bundle_present": 1}
    )
    assert odd is not None
    assert (odd.installed, odd.vm_bundle_bytes, odd.cowork_plugins, odd.vm_bundle_present) == (False, 0, (), False)
    assert ClaudeDesktopInfo.from_mapping({"installed": True, "vm_bundle_bytes": -5}).vm_bundle_bytes == 0


@pytest.mark.parametrize(
    ("size", "text"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (10 << 30, "10.0 GiB"),
        (3 << 40, "3.0 TiB"),
        (5000 << 40, "5000.0 TiB"),
    ],
)
def test_format_bytes(size: int, text: str) -> None:
    assert format_bytes(size) == text


def test_usage_detail_shows_the_block_only_when_a_signal_has_one() -> None:
    plain = cmd_agent._render_ai_usage_table({"signals": [_signal(None)]}, detail=True)
    assert "Claude Desktop" in plain  # the product
    assert "cowork" not in plain
    out = cmd_agent._render_ai_usage_table({"signals": [_signal(COWORK_MAC)]}, detail=True)
    # The table wraps the cell: check its pieces.
    for piece in ("Claude Desktop", "4.4212.0", "2.1.309", "(cowork_sessions)", "11.3", "sales-tools"):
        assert piece in out


def test_usage_detail_plain_fallback_keeps_its_columns_without_a_block() -> None:
    without = cmd_agent._render_ai_usage_plain({"signals": [_signal(None)]}, detail=True)
    with_block = cmd_agent._render_ai_usage_plain({"signals": [_signal(COWORK_MAC)]}, detail=True)
    assert without.splitlines()[1].count(" | ") + 1 == with_block.splitlines()[1].count(" | ")
    assert "cowork on (cowork_sessions)" in with_block


def test_usage_json_passes_the_block_through_untouched() -> None:
    payload = {"signals": [_signal(COWORK_MAC)]}
    assert json.loads(json.dumps(payload))["signals"][0]["claude_desktop"] == COWORK_MAC


def test_tui_detail_lists_the_block() -> None:
    now = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
    sig = _signal({**COWORK_MAC, "cowork_enabled": None, "cowork_enabled_source": ""})
    snapshot = AIUsageSnapshot.from_mapping(
        {"enabled": True, "signals": [sig, _signal(None) | {"signal_id": "s2", "detector": "config"}]}
    )
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(snapshot)
    assert snapshot.signals[0].claude_desktop is not None
    assert snapshot.signals[1].claude_desktop is None
    panel.toggle_detail()
    detail = "\n".join(panel.detail_lines(now=now))
    assert "claude desktop: app 4.4212.0; engine 2.1.309; cowork unknown; vm bundle 11.3 GiB" in detail
    assert detail.count("claude desktop:") == 1


def test_summary_names_the_deployment() -> None:
    """GAP-0024 (cowork-1-0-8): a third-party inference install says so."""
    third = ClaudeDesktopInfo.from_mapping({"installed": True, "deployment": "3p", "engine_version": "2.1.317"})
    assert third is not None and third.deployment == "3p"
    assert third.summary().startswith("app installed; third-party inference; engine 2.1.317;")
    first = ClaudeDesktopInfo.from_mapping({"installed": True, "deployment": "1p"})
    assert first is not None and "Claude account" in first.summary()
    for bad in ("2p", ["3p"], {"x": 1}, 3):
        info = ClaudeDesktopInfo.from_mapping({"installed": True, "deployment": bad})
        assert info is not None and info.deployment == ""
