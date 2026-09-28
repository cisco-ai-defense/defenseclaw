# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared TUI test fixtures."""

from __future__ import annotations

import inspect
import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def current_windows_gateway(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one current-source gateway before per-test HOME isolation.

    The suite intentionally assigns every Windows test a fresh USERPROFILE.
    Go derives its module cache from that profile, so compiling inside an
    individual test redownloads the complete dependency graph and can exceed
    the shard timeout. A session-scoped build both preserves isolation and
    shares the already authenticated runner cache across the two native TUI
    lifecycle contracts.
    """

    if os.name != "nt":
        pytest.skip("native Windows gateway fixture")
    output_dir = tmp_path_factory.mktemp("current-windows-gateway")
    binary = output_dir / "defenseclaw-gateway.exe"
    build_log = output_dir / "go-build.log"
    repo_root = Path(__file__).resolve().parents[3]
    with build_log.open("wb") as output:
        completed = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), "./cmd/defenseclaw"],
            cwd=repo_root,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
            # Hosted Windows can exceed five minutes when the current gateway
            # is rebuilt while the native Go matrix is also compiling. Keep
            # the fixture bounded, but leave enough room for that cold path.
            timeout=600,
        )
    assert completed.returncode == 0, build_log.read_text(encoding="utf-8", errors="replace")
    return binary


@pytest.fixture(scope="session")
def current_windows_claude_version_probe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build a native, version-probe-only Claude fixture without a live client."""

    if os.name != "nt":
        pytest.skip("native Windows Claude version fixture")
    output_dir = tmp_path_factory.mktemp("current-windows-claude-version")
    source = output_dir / "main.go"
    binary = output_dir / "claude.exe"
    build_log = output_dir / "go-build.log"
    source.write_text(
        """package main

import (
    "fmt"
    "os"
)

func main() {
    if len(os.Args) == 2 && os.Args[1] == "--version" {
        fmt.Println("2.1.154 (Claude Code)")
        return
    }
    os.Exit(2)
}
""",
        encoding="utf-8",
    )
    with build_log.open("wb") as output:
        completed = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), str(source)],
            cwd=Path(__file__).resolve().parents[3],
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
            # Hosted Windows can spend over a minute scheduling and priming a
            # cold Go cache. Keep the build bounded with the allowance used by
            # other native one-file test fixtures.
            timeout=180,
        )
    assert completed.returncode == 0, build_log.read_text(encoding="utf-8", errors="replace")
    return binary


@pytest.fixture(autouse=True)
def _no_sandbox_machine_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never run the real ``sandbox doctor`` when a test opens the Sandbox wizard."""

    from defenseclaw.tui import sandbox_panel
    from defenseclaw.tui.panels.setup import sandbox_machine_check

    monkeypatch.setattr(
        sandbox_panel, "probe_sandbox_machine", lambda: sandbox_machine_check(None, "not probed in tests")
    )


@pytest.fixture(autouse=True)
def _no_agent_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never scan the host for installed agents (binaries, configs, versions).

    Tests that need specific agents patch ``discover_agents`` themselves; a
    ``patch.object`` inside the test body replaces this stub for its scope.
    """

    from defenseclaw.inventory import agent_discovery

    def _empty_discovery(*_args: object, **_kwargs: object) -> agent_discovery.AgentDiscovery:
        return agent_discovery.AgentDiscovery(scanned_at="test", agents={}, cache_hit=True)

    monkeypatch.setattr(agent_discovery, "discover_agents", _empty_discovery)


@pytest.fixture(autouse=True)
def _no_captured_cli_refresh(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never spawn the real CLI for the app's quiet ``--json`` loads in Pilot tests.

    After a (faked) command succeeds the running app reloads panel data
    through ``_communicate_captured``, which would run ``defenseclaw ...
    --json`` against the developer's real home. Only ``tui_pilot`` tests are
    stubbed: unit tests of the loaders fake ``create_subprocess_exec`` and
    need the real helper. A Pilot test that wants a load patches it again.
    """

    if request.node.get_closest_marker("tui_pilot") is None:
        return

    from defenseclaw.tui import app as app_module

    async def _not_run(binary: str, args: tuple[str, ...]) -> tuple[int, bytes, bytes]:
        return 1, b"", b"captured CLI calls are disabled in TUI tests"

    monkeypatch.setattr(app_module, "_communicate_captured", _not_run)


def _uses_pilot(item: pytest.Item) -> bool:
    function = getattr(item, "function", None)
    if function is None:
        return False
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError):
        return False
    return "run_test(" in source


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every test that drives the app through ``run_test`` as ``tui_pilot``."""

    tui_dir = Path(__file__).resolve().parent
    for item in items:
        try:
            in_tui = Path(str(item.fspath)).resolve().is_relative_to(tui_dir)
        except (OSError, ValueError):
            continue
        if in_tui and _uses_pilot(item):
            item.add_marker(pytest.mark.tui_pilot)
