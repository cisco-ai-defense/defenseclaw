# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Windows connector status, presentation, and direct-setup parity."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_init import _normalize_connector_arg, init_cmd
from defenseclaw.commands.cmd_setup import (
    _CONNECTOR_NAMES_FALLBACK,
    _HOOK_ENFORCED_CONNECTORS,
    _PROXY_BACKED_CONNECTORS,
)
from defenseclaw.commands.cmd_setup import (
    setup as setup_group,
)
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.context import AppContext
from defenseclaw.platform_support import (
    PREVIEW,
    PROXY_CONNECTORS,
    SUPPORTED,
    UNSUPPORTED,
    WINDOWS_CONNECTOR_SUPPORT,
    WINDOWS_PREVIEW_CONNECTORS,
    WINDOWS_SUPPORTED_CONNECTORS,
    WINDOWS_UNSUPPORTED_CONNECTORS,
    connector_platform_support,
    connector_preview_on_os,
    connector_supported_on_os,
    host_os,
    is_proxy_connector,
    supported_connectors,
)
from defenseclaw.tui.panels.first_run import CONNECTOR_CHOICES, visible_connector_choices
from defenseclaw.tui.screens.mode_picker import (
    MODE_PICKER_CHOICES,
    visible_mode_picker_choices,
)
from defenseclaw.tui.services.cli_choices import (
    CONNECTORS,
    GUARDRAIL_CONNECTORS,
    supported_connector_choices,
)

from tests.helpers import cleanup_app, make_app_context

WINDOWS_SUPPORTED = {
    "codex",
    "claudecode",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "antigravity",
    "opencode",
}
WINDOWS_PREVIEW = {"hermes"}
WINDOWS_UNSUPPORTED = {"openhands", "omnigent", "openclaw", "zeptoclaw"}
ALL_CONNECTORS = WINDOWS_SUPPORTED | WINDOWS_PREVIEW | WINDOWS_UNSUPPORTED


def test_windows_taxonomy_matches_go_mirror_and_has_reasons() -> None:
    assert set(WINDOWS_CONNECTOR_SUPPORT) == ALL_CONNECTORS
    assert set(WINDOWS_SUPPORTED_CONNECTORS) == WINDOWS_SUPPORTED
    assert set(WINDOWS_PREVIEW_CONNECTORS) == WINDOWS_PREVIEW
    assert set(WINDOWS_UNSUPPORTED_CONNECTORS) == WINDOWS_UNSUPPORTED
    for name, support in WINDOWS_CONNECTOR_SUPPORT.items():
        assert support.status in {SUPPORTED, PREVIEW, UNSUPPORTED}, name
        assert support.reason.strip(), name

    go_source = (
        Path(__file__).resolve().parents[2]
        / "internal"
        / "gateway"
        / "connector"
        / "platform_support.go"
    ).read_text(encoding="utf-8")
    go_status = {
        SUPPORTED: "PlatformSupported",
        PREVIEW: "PlatformPreview",
        UNSUPPORTED: "PlatformUnsupported",
    }
    for name, support in WINDOWS_CONNECTOR_SUPPORT.items():
        pattern = (
            rf'"{re.escape(name)}":\s*\{{\s*'
            rf'Status:\s*{go_status[support.status]},\s*'
            rf'Reason:\s*"{re.escape(support.reason)}",'
        )
        assert re.search(pattern, go_source), f"Go status/reason drift for {name}"


def test_proxy_topology_is_distinct_from_windows_support() -> None:
    assert set(PROXY_CONNECTORS) == {"openclaw", "zeptoclaw"}
    assert set(GUARDRAIL_CONNECTORS) == set(PROXY_CONNECTORS)
    assert set(_PROXY_BACKED_CONNECTORS) == set(PROXY_CONNECTORS)
    assert is_proxy_connector("openclaw")
    assert is_proxy_connector("zeptoclaw")
    assert not is_proxy_connector("openhands")
    assert not is_proxy_connector("omnigent")


def test_windows_statuses_and_availability() -> None:
    for name in WINDOWS_SUPPORTED:
        assert connector_platform_support(name, "windows").status == SUPPORTED
        assert connector_supported_on_os(name, "windows") is True
    for name in WINDOWS_PREVIEW:
        assert connector_platform_support(name, "windows").status == PREVIEW
        assert connector_preview_on_os(name, "windows") is True
        assert connector_supported_on_os(name, "windows") is True
    for name in WINDOWS_UNSUPPORTED:
        assert connector_platform_support(name, "windows").status == UNSUPPORTED
        assert connector_supported_on_os(name, "windows") is False


def test_cursor_reason_distinguishes_native_ide_from_wsl_only_cli() -> None:
    reason = connector_platform_support("cursor", "windows").reason
    assert "IDE hooks" in reason
    assert "CLI remains WSL-only" in reason


def test_non_windows_behavior_is_unchanged() -> None:
    for os_name in ("linux", "darwin"):
        for name in ALL_CONNECTORS:
            support = connector_platform_support(name, os_name)
            assert support.status == SUPPORTED
            assert support.available


def test_supported_connectors_preserves_order_and_keeps_preview() -> None:
    ordered = ["openclaw", "codex", "hermes", "openhands", "claudecode"]
    assert supported_connectors(ordered, "windows") == ["codex", "hermes", "claudecode"]
    assert supported_connectors(ordered, "linux") == ordered


def test_host_os_returns_known_token() -> None:
    assert host_os() in {"windows", "darwin", "linux"} or isinstance(host_os(), str)


def test_all_connector_lists_share_one_taxonomy() -> None:
    assert set(KNOWN_CONNECTORS) == ALL_CONNECTORS
    assert set(_CONNECTOR_NAMES_FALLBACK) == ALL_CONNECTORS
    assert set(CONNECTORS) == ALL_CONNECTORS
    assert {choice.wire for choice in MODE_PICKER_CHOICES} == ALL_CONNECTORS
    assert set(CONNECTOR_CHOICES) == ALL_CONNECTORS
    assert set(_HOOK_ENFORCED_CONNECTORS) == ALL_CONNECTORS - set(PROXY_CONNECTORS)


def test_windows_views_hide_unsupported_and_mark_hermes_preview() -> None:
    expected = WINDOWS_SUPPORTED | WINDOWS_PREVIEW
    assert set(supported_connector_choices("windows")) == expected
    assert set(visible_connector_choices("windows")) == expected

    win_modes = visible_mode_picker_choices("windows")
    assert {choice.wire for choice in win_modes} == expected
    hermes = next(choice for choice in win_modes if choice.wire == "hermes")
    assert hermes.label == "Hermes (preview)"
    assert "Early Beta" in hermes.tagline


def test_non_windows_views_are_unfiltered() -> None:
    assert supported_connector_choices("linux") == CONNECTORS
    assert visible_mode_picker_choices("darwin") == MODE_PICKER_CHOICES
    assert visible_connector_choices("linux") == CONNECTOR_CHOICES


def test_discovery_default_preserves_non_windows_and_avoids_unsupported_windows() -> None:
    discovery = object()
    with patch(
        "defenseclaw.commands.cmd_init.agent_discovery.discover_agents",
        return_value=discovery,
    ), patch(
        "defenseclaw.commands.cmd_init.agent_discovery.first_installed",
        return_value="openclaw",
    ), patch("defenseclaw.platform_support.host_os", return_value="linux"):
        assert _normalize_connector_arg(None, discover_default=True) == "openclaw"

    with patch(
        "defenseclaw.commands.cmd_init.agent_discovery.discover_agents",
        return_value=discovery,
    ), patch(
        "defenseclaw.commands.cmd_init.agent_discovery.first_installed",
        return_value="openclaw",
    ), patch(
        "defenseclaw.commands.cmd_init._installed_hook_connectors",
        return_value=["codex"],
    ), patch("defenseclaw.platform_support.host_os", return_value="windows"):
        assert _normalize_connector_arg(None, discover_default=True) == "codex"


def test_direct_windows_setup_rejects_unsupported_with_reason() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        runner = CliRunner()
        with patch("defenseclaw.platform_support.host_os", return_value="windows"):
            openhands = runner.invoke(
                setup_group,
                ["openhands", "--yes", "--no-restart"],
                obj=app,
            )
            omnigent = runner.invoke(
                setup_group,
                ["omnigent", "--yes", "--no-restart"],
                obj=app,
            )
        assert openhands.exit_code != 0
        assert "unsupported on windows" in openhands.output
        assert "requires WSL" in openhands.output
        assert omnigent.exit_code != 0
        assert "unsupported on windows" in omnigent.output
        assert "no supported native Windows" in omnigent.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_bare_windows_setup_rejects_explicit_unsupported_before_mutation() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        runner = CliRunner()
        with patch("defenseclaw.platform_support.host_os", return_value="windows"):
            result = runner.invoke(
                setup_group,
                ["--connector", "openhands", "--yes", "--no-restart"],
                obj=app,
            )
        assert result.exit_code != 0
        assert "requires WSL" in result.output
        assert app.cfg.guardrail.connectors == {}
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_guardrail_windows_setup_rejects_unsupported_before_mutation() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        original = app.cfg.guardrail.connector
        with patch("defenseclaw.platform_support.host_os", return_value="windows"):
            result = CliRunner().invoke(
                setup_group,
                [
                    "guardrail",
                    "--connector",
                    "openhands",
                    "--non-interactive",
                    "--no-restart",
                    "--no-verify",
                ],
                obj=app,
            )
        assert result.exit_code != 0
        assert "requires WSL" in result.output
        assert app.cfg.guardrail.connector == original
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_noninteractive_windows_init_rejects_unsupported_before_bootstrap() -> None:
    with patch("defenseclaw.platform_support.host_os", return_value="windows"):
        result = CliRunner().invoke(
            init_cmd,
            ["--non-interactive", "--yes", "--connector", "openhands"],
            obj=AppContext(),
        )
    assert result.exit_code != 0
    assert "unsupported on windows" in result.output
    assert "requires WSL" in result.output
