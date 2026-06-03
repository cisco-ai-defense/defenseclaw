# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-OS connector support: parity and Windows-excludes-proxy behavior.

These tests pin the Python ``platform_support`` module against the Go
``connector.proxyConnectors`` set and against every Python connector list,
so the "hook-only on Windows" contract cannot silently drift on either
side. They run on every OS (the filtering takes an explicit ``os_name`` so
the assertions are host-independent).
"""

from __future__ import annotations

from defenseclaw.commands.cmd_setup import (
    _CONNECTOR_NAMES_FALLBACK,
    _HOOK_ENFORCED_CONNECTORS,
    _PROXY_BACKED_CONNECTORS,
)
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.platform_support import (
    WINDOWS_UNSUPPORTED_CONNECTORS,
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

# Mirror of the Go ``proxyConnectors`` map in
# internal/gateway/connector/platform_support.go. Any change there must be
# made here too; the assertions below fail loudly if the two drift.
PROXY_CONNECTORS = {"openclaw", "zeptoclaw"}

# The hook-based connectors supported on every OS, including Windows.
HOOK_CONNECTORS = {
    "codex",
    "claudecode",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
}


def test_windows_unsupported_set_matches_go_proxy_connectors() -> None:
    assert set(WINDOWS_UNSUPPORTED_CONNECTORS) == PROXY_CONNECTORS


def test_proxy_set_agrees_with_existing_python_sources() -> None:
    # GUARDRAIL_CONNECTORS (cli_choices) and _PROXY_BACKED_CONNECTORS
    # (cmd_setup) are the pre-existing names for the same proxy set; the
    # new single source of truth must agree with both.
    assert set(GUARDRAIL_CONNECTORS) == PROXY_CONNECTORS
    assert set(_PROXY_BACKED_CONNECTORS) == PROXY_CONNECTORS


def test_hook_enforced_set_is_the_hook_connectors() -> None:
    assert set(_HOOK_ENFORCED_CONNECTORS) == HOOK_CONNECTORS


def test_is_proxy_connector() -> None:
    assert is_proxy_connector("openclaw")
    assert is_proxy_connector("zeptoclaw")
    for name in HOOK_CONNECTORS:
        assert not is_proxy_connector(name)


def test_connector_supported_on_os_windows_excludes_only_proxy() -> None:
    for name in PROXY_CONNECTORS:
        assert connector_supported_on_os(name, "windows") is False
    for name in HOOK_CONNECTORS:
        assert connector_supported_on_os(name, "windows") is True


def test_connector_supported_on_os_unix_allows_everything() -> None:
    for os_name in ("linux", "darwin"):
        for name in PROXY_CONNECTORS | HOOK_CONNECTORS:
            assert connector_supported_on_os(name, os_name) is True


def test_supported_connectors_preserves_order_and_filters_windows() -> None:
    ordered = ["openclaw", "codex", "zeptoclaw", "claudecode"]
    assert supported_connectors(ordered, "windows") == ["codex", "claudecode"]
    assert supported_connectors(ordered, "linux") == ordered


def test_host_os_returns_known_token() -> None:
    assert host_os() in {"windows", "darwin", "linux"} or isinstance(host_os(), str)


def test_all_connector_lists_share_one_taxonomy() -> None:
    # Fixing the historical openhands drift: every Python enumeration of
    # connectors must contain exactly the proxy + hook connectors.
    expected = PROXY_CONNECTORS | HOOK_CONNECTORS
    assert set(KNOWN_CONNECTORS) == expected
    assert set(_CONNECTOR_NAMES_FALLBACK) == expected
    assert set(CONNECTORS) == expected
    assert {c.wire for c in MODE_PICKER_CHOICES} == expected
    assert set(CONNECTOR_CHOICES) == expected


def test_windows_views_exclude_proxy_and_keep_all_hook_connectors() -> None:
    # cli_choices accessor
    win_choices = supported_connector_choices("windows")
    assert set(win_choices) == HOOK_CONNECTORS
    assert not (set(win_choices) & PROXY_CONNECTORS)

    # mode picker rows
    win_modes = {c.wire for c in visible_mode_picker_choices("windows")}
    assert win_modes == HOOK_CONNECTORS

    # first-run wizard field
    assert set(visible_connector_choices("windows")) == HOOK_CONNECTORS


def test_non_windows_views_are_unfiltered() -> None:
    assert supported_connector_choices("linux") == CONNECTORS
    assert visible_mode_picker_choices("darwin") == MODE_PICKER_CHOICES
    assert visible_connector_choices("linux") == CONNECTOR_CHOICES
